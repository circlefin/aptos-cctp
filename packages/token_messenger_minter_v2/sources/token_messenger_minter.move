/// Copyright (c) 2025, Circle Internet Group, Inc.
/// All rights reserved.
///
/// SPDX-License-Identifier: Apache-2.0
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
/// http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

/// Main business logic module for TokenMessengerMinter.
/// Handles both outbound (deposit_for_burn) and inbound (prepare_mint, complete_mint) flows.
/// Provides handler support for multi-token architecture.
module token_messenger_minter_v2::token_messenger_minter {
    // Built-in Modules
    use std::error;
    use std::signer;
    use aptos_framework::event;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::fungible_asset::{Self, FungibleAsset, Metadata};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_extensions::ownable;
    use aptos_extensions::pausable;
    use aptos_framework::block;

    // External Package Modules
    use message_transmitter_v2::message_transmitter::{Self, Receipt};

    // Package Modules
    use token_messenger_minter_v2::state;
    use token_messenger_minter_v2::burn_message;
    use token_messenger_minter_v2::token_controller;
    use token_messenger_minter_v2::handler_registry;
    use token_messenger_minter_v2::initializer;
    use token_messenger_minter_v2::denylistable;
    use token_messenger_minter_v2::fee_controller;

    // Errors
    const EINVALID_AMOUNT: u64 = 1;
    const EINVALID_MINT_RECIPIENT_ADDRESS: u64 = 2;
    const EINVALID_MAX_FEE: u64 = 3;
    const EINSUFFICIENT_MAX_FEE: u64 = 4;
    const ETOKEN_MESSENGER_ALREADY_SET: u64 = 5;
    const ENO_TOKEN_MESSENGER_SET_FOR_DOMAIN: u64 = 6;
    const ENOT_TOKEN_MESSENGER: u64 = 7;
    const EINVALID_MESSAGE_BODY_VERSION: u64 = 8;
    const ERECIPIENT_NOT_TOKEN_MESSENGER: u64 = 9;
    const EUNSUPPORTED_DESTINATION_DOMAIN: u64 = 10;
    const EINVALID_TOKEN_MESSENGER_ADDRESS: u64 = 11;
    const EEXPIRED_MESSAGE: u64 = 12;
    const EFEE_EQUALS_OR_EXCEEDS_AMOUNT: u64 = 13;
    const EFEE_EXCEEDS_MAX_FEE: u64 = 14;
    const EINVALID_FEE: u64 = 15;
    const EINVALID_ASSET_METADATA: u64 = 16;
    const EINVALID_FEE_ASSET_METADATA: u64 = 17;
    const EUNSUPPORTED_FINALITY_THRESHOLD_EXECUTED: u64 = 18;
    const EASSET_METADATA_MISMATCH: u64 = 19;

    // Constants
    const MAX_U64: u256 = 18_446_744_073_709_551_615;
    const MIN_FINALITY_THRESHOLD_EXECUTED: u32 = 500;

    // -----------------------------
    // ---------- Events -----------
    // -----------------------------

    #[event]
    struct DepositForBurn has drop, store {
        burn_token: address,
        amount: u64,
        depositor: address,
        mint_recipient: address,
        destination_domain: u32,
        destination_token_messenger: address,
        destination_caller: address,
        max_fee: u64,
        min_finality_threshold: u32,
        hook_data: vector<u8>,
    }

    #[event]
    struct MintAndWithdraw has drop, store {
        mint_recipient: address,
        amount: u64,
        mint_token: address,
        fee_collected: u64
    }

    #[event]
    struct RemoteTokenMessengerAdded has drop, store {
        domain: u32,
        token_messenger: address
    }

    #[event]
    struct RemoteTokenMessengerRemoved has drop, store {
        domain: u32,
        token_messenger: address
    }

    // -----------------------------
    // -------- MintReceipt --------
    // -----------------------------

    /// Hot potato struct (no abilities) that wraps Receipt with mint details.
    /// Created by prepare_mint(), consumed by complete_mint().
    /// Cannot be dropped, copied, or stored - must be consumed in same transaction.
    struct MintReceipt {
        /// The underlying message transmitter receipt
        receipt: Receipt,
        /// The local token address to mint
        local_token: address,
        /// The recipient address for the minted tokens (from burn message)
        mint_recipient: address,
        /// The amount to mint to mint_recipient
        amount: u64,
        /// The fee for the mint
        fee: u64,
    }

    // -----------------------------
    // -------- BurnReceipt --------
    // -----------------------------

    /// Hot potato struct (no abilities) for outbound burns.
    /// Created by deposit_for_burn(), consumed by complete_burn().
    /// Cannot be dropped, copied, or stored - must be consumed in same transaction.
    struct BurnReceipt {
        /// The caller who initiated the burn
        caller: address,
        /// The token address being burned
        burn_token: address,
        /// The amount being burned
        amount: u64,
        /// The destination domain for the cross-chain transfer
        destination_domain: u32,
        /// The recipient address on the destination chain
        mint_recipient: address,
        /// The caller restriction on destination (0x0 for none)
        destination_caller: address,
        /// The token messenger on the destination chain
        destination_token_messenger: address,
        /// The max fee for the burn
        max_fee: u64,
        /// The min finality threshold for the burn
        min_finality_threshold: u32,
        /// The hook data for the burn
        hook_data: vector<u8>,
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    public fun message_body_version(): u32 {
        state::get_message_body_version()
    }

    #[view]
    public fun remote_token_messenger(domain: u32): address {
        state::get_remote_token_messenger(domain)
    }

    #[view]
    public fun num_remote_token_messengers(): u64 {
        state::get_num_remote_token_messengers()
    }

    #[view]
    public fun max_burn_amount_per_message(token: address): u64 {
        let (_, max_burn_amount) = state::get_max_burn_limit_per_message_for_token(token);
        max_burn_amount
    }

    // -----------------------------
    // ----- Outbound Functions ----
    // -----------------------------

    /// Validates the burn parameters and returns a BurnReceipt along with the asset.
    /// The handler should burn the asset and call complete_burn() to finalize.
    /// If destination_caller is non-zero, the mint on destination must be called by that address.
    ///
    /// Aborts if:
    /// - contract is paused
    /// - caller is denylisted
    /// - amount is zero
    /// - mint recipient is zero address
    /// - max_fee >= amount
    /// - max_fee is less than the minimum fee for the burn token (when min fee > 0)
    /// - destination domain has no TokenMessenger registered
    /// - amount exceeds burn limit for token
    public fun deposit_for_burn(
        caller: &signer,
        asset: FungibleAsset,
        destination_domain: u32,
        mint_recipient: address,
        destination_caller: address,
        max_fee: u64,
        min_finality_threshold: u32,
        hook_data: vector<u8>,
    ): (BurnReceipt, FungibleAsset) {
        create_burn_receipt(
            caller,
            asset,
            destination_domain,
            mint_recipient,
            destination_caller,
            max_fee,
            min_finality_threshold,
            hook_data,
        )
    }

    // -----------------------------
    // ----- Inbound Functions -----
    // -----------------------------

    /// Validates a cross-chain message Receipt and creates a MintReceipt for handlers.
    /// The MintReceipt is a hot potato that must be consumed by complete_mint().
    ///
    /// Aborts if:
    /// - contract is paused
    /// - recipient in receipt is not TokenMessengerMinter object
    /// - sender in receipt is not the registered remote token messenger for source domain
    /// - message body is not a valid burn message
    /// - message body version doesn't match
    /// - message has expired (expiration_block > 0 and expiration_block <= current_block)
    /// - amount exceeds MAX_U64
    /// - fee equals or exceeds amount (when fee != 0)
    /// - fee exceeds max_fee
    /// - finality threshold executed is less than MIN_FINALITY_THRESHOLD_EXECUTED
    public fun prepare_mint(receipt: Receipt): MintReceipt {
        // check if the contract is paused
        pausable::assert_not_paused(state::get_object_address());

        let (sender, recipient, remote_domain, _caller, finality_threshold_executed, message_body) = message_transmitter::get_receipt_details(&receipt);

        // Validate finality threshold executed
        assert!(finality_threshold_executed >= MIN_FINALITY_THRESHOLD_EXECUTED, error::invalid_argument(EUNSUPPORTED_FINALITY_THRESHOLD_EXECUTED));

        // Validate `recipient` in receipt is the `TokenMessengerMinter` contract
        assert!(recipient == state::get_object_address(), error::invalid_argument(ERECIPIENT_NOT_TOKEN_MESSENGER));

        // Validate `sender` in receipt is a remote token messenger for `remote_domain`
        validate_remote_token_messenger(remote_domain, sender);

        // Verify message body is a valid burn message (V2 format)
        burn_message::validate_message(&message_body);

        // Verify message body version matches the one included in the burn message
        let message_version = burn_message::get_version(&message_body);
        assert!(message_version == message_body_version(), error::invalid_argument(EINVALID_MESSAGE_BODY_VERSION));

        // Enforce message expiration
        let expiration_block = burn_message::get_expiration_block(&message_body);
        if (expiration_block != 0) {
            let current_block = block::get_current_block_height();
            assert!(expiration_block > (current_block as u256), error::invalid_argument(EEXPIRED_MESSAGE));
        };

        // Get amount and fees
        let amount = burn_message::get_amount(&message_body);
        let fee = burn_message::get_fee_executed(&message_body);
        let max_fee = burn_message::get_max_fee(&message_body);

        // Validate amount doesn't exceed MAX_U64
        assert!(amount <= MAX_U64, error::invalid_argument(EINVALID_AMOUNT));

        // Validate fee doesn't equal or exceed amount
        if (fee != 0) {
            assert!(fee < amount, error::invalid_argument(EFEE_EQUALS_OR_EXCEEDS_AMOUNT));
        };

        // Validate fee doesn't exceed max fee
        assert!(fee <= max_fee, error::invalid_argument(EFEE_EXCEEDS_MAX_FEE));

        // Extract mint details from burn message
        let mint_recipient = burn_message::get_mint_recipient(&message_body);
        let burn_token = burn_message::get_burn_token(&message_body);

        // Look up local token from token pair mapping
        let local_token = token_controller::get_linked_token(remote_domain, burn_token);

        MintReceipt {
            receipt,
            local_token,
            mint_recipient,
            amount: ((amount - fee) as u64),
            fee: (fee as u64),
        }
    }

    /// Returns the mint details from a MintReceipt without consuming it.
    /// Handlers use this to get the local_token, mint_recipient, amount, and fee.
    ///
    /// Returns: (local_token, mint_recipient, amount, fee)
    public fun get_mint_details(mint_receipt: &MintReceipt): (address, address, u64, u64) {
        (
            mint_receipt.local_token,
            mint_receipt.mint_recipient,
            mint_receipt.amount,
            mint_receipt.fee,
        )
    }

    /// Handler calls this to get TMM signer for minting/burning with treasury.
    /// Returns the TokenMessengerMinter signer after verifying the handler is registered.
    ///
    /// Aborts if:
    /// - handler is not registered for the token
    public fun get_signer_for_handler(
        handler_signer: &signer,
        token_address: address,
    ): signer {
        // Verify handler is registered for this token
        handler_registry::assert_is_registered_handler(handler_signer, token_address);

        // Return shared TMM signer
        initializer::get_signer()
    }

    /// Completes the mint flow by depositing assets and consuming the MintReceipt.
    /// This function:
    /// 1. Verifies handler is registered (defense in depth)
    /// 2. Verifies asset amounts match the receipt amounts
    /// 3. Deposits minted asset to mint_recipient
    /// 4. Deposits fee asset to fee_recipient
    /// 5. Emits MintAndWithdraw event
    /// 6. Destroys the underlying Receipt via message_transmitter
    ///
    /// Aborts if:
    /// - handler is not registered for this token
    /// - asset amount doesn't match receipt amount
    /// - asset metadata doesn't match the local token
    /// - fee_asset amount doesn't match receipt fee
    /// - fee asset metadata doesn't match the local token
    /// - the recipient has an existing store with a different metadata
    public fun complete_mint(
        handler_signer: &signer,
        mint_receipt: MintReceipt,
        asset: FungibleAsset,
        fee_asset: FungibleAsset,
    ) {
        let MintReceipt {
            receipt,
            local_token,
            mint_recipient,
            amount,
            fee,
        } = mint_receipt;

        // Verify handler is registered (defense in depth)
        handler_registry::assert_is_registered_handler(handler_signer, local_token);
        assert!(amount == fungible_asset::amount(&asset), error::invalid_argument(EINVALID_AMOUNT));
        assert!(fee == fungible_asset::amount(&fee_asset), error::invalid_argument(EINVALID_FEE));

        // verify asset metadata matches the local token
        let asset_metadata = asset.asset_metadata();
        assert!(asset_metadata.object_address() == local_token, error::invalid_argument(EINVALID_ASSET_METADATA));

        // verify fee asset metadata matches the local token
        let fee_asset_metadata = fee_asset.asset_metadata();
        assert!(fee_asset_metadata.object_address() == local_token, error::invalid_argument(EINVALID_FEE_ASSET_METADATA));

        let token_obj = object::address_to_object<Metadata>(local_token);

        // Deposit minted asset to the mint recipient
        deposit_asset(mint_recipient, token_obj, asset, amount);

        let fee_recipient = fee_controller::get_fee_recipient();

        // Deposit fee to fee recipient
        deposit_asset(fee_recipient, token_obj, fee_asset, fee);

        // Emit event
        event::emit(MintAndWithdraw {
            mint_recipient,
            amount,
            mint_token: local_token,
            fee_collected: fee,
        });

        // Destroy Receipt via message_transmitter
        let token_messenger_minter_signer = initializer::get_signer();
        message_transmitter::complete_receive_message(&token_messenger_minter_signer, receipt);
    }

    fun deposit_asset(recipient: address, token_obj: Object<Metadata>, asset: FungibleAsset, amount: u64) {
        if (amount > 0) {
            let store = if (fungible_asset::store_exists(recipient)) {
                let existing_store = object::address_to_object<fungible_asset::FungibleStore>(recipient);
                assert!(fungible_asset::store_metadata(existing_store) == token_obj, error::invalid_argument(EASSET_METADATA_MISMATCH));
                existing_store
            } else {
                primary_fungible_store::ensure_primary_store_exists(recipient, token_obj)
            };

            dispatchable_fungible_asset::deposit(store, asset);
        } else {
            asset.destroy_zero();
        };
    }

    // -----------------------------
    // --- Burn Receipt Functions --
    // -----------------------------

    /// Returns the burn details from a BurnReceipt without consuming it.
    /// Handlers use this to verify the token and amount before burning.
    ///
    /// Returns: (burn_token, amount, mint_recipient)
    public fun get_burn_details(burn_receipt: &BurnReceipt): (address, u64, address) {
        (
            burn_receipt.burn_token,
            burn_receipt.amount,
            burn_receipt.mint_recipient,
        )
    }


    /// Completes the burn flow by sending the cross-chain message and emitting event.
    /// This function:
    /// 1. Verifies handler is registered (defense in depth)
    /// 2. Creates and sends the burn message via message_transmitter
    /// 3. Emits DepositForBurn event
    /// 4. Destroys the BurnReceipt (consumes hot potato)
    ///
    /// Aborts if:
    /// - handler is not registered for this token
    public fun complete_burn(
        handler_signer: &signer,
        burn_receipt: BurnReceipt,
    ) {
        let BurnReceipt {
            caller,
            burn_token,
            amount,
            destination_domain,
            mint_recipient,
            destination_caller,
            destination_token_messenger,
            max_fee,
            min_finality_threshold,
            hook_data,
        } = burn_receipt;

        // Verify handler is registered (defense in depth)
        handler_registry::assert_is_registered_handler(handler_signer, burn_token);

        // Create burn message
        let serialized_burn_message = burn_message::serialize(
            message_body_version(),
            burn_token,
            mint_recipient,
            (amount as u256),
            caller,
            max_fee as u256,
            &hook_data
        );

        // Send message via message_transmitter
        send_deposit_for_burn(
            destination_domain,
            destination_token_messenger,
            destination_caller,
            min_finality_threshold,
            &serialized_burn_message
        );

        // Emit event
        event::emit(DepositForBurn {
            burn_token,
            amount,
            depositor: caller,
            mint_recipient,
            destination_domain,
            destination_token_messenger,
            destination_caller,
            max_fee,
            min_finality_threshold,
            hook_data,
        });
    }

    // -----------------------------
    // ----- Admin Functions -------
    // -----------------------------

    /// Add TokenMessenger for a remote domain. Emits `RemoteTokenMessengerAdded` event
    /// Aborts if:
    /// - caller is not the owner
    /// - TokenMessenger is zero address
    /// - there is already a TokenMessenger set for domain
    entry fun add_remote_token_messenger(caller: &signer, domain: u32, token_messenger: address) {
        ownable::assert_is_owner(caller, state::get_object_address());
        assert!(token_messenger != @0x0, error::invalid_argument(EINVALID_TOKEN_MESSENGER_ADDRESS));
        assert!(
            !state::is_remote_token_messenger_set_for_domain(domain),
            error::already_exists(ETOKEN_MESSENGER_ALREADY_SET)
        );
        state::add_remote_token_messenger(domain, token_messenger);
        event::emit(RemoteTokenMessengerAdded { domain, token_messenger } );
    }

    /// Remove TokenMessenger for a remote domain. Emits `RemoteTokenMessengerRemoved` event
    /// Aborts if:
    /// - caller is not the owner
    /// - there is no TokenMessenger set for domain
    entry fun remove_remote_token_messenger(caller: &signer, domain: u32) {
        ownable::assert_is_owner(caller, state::get_object_address());
        assert!(
            state::is_remote_token_messenger_set_for_domain(domain),
            error::invalid_argument(ENO_TOKEN_MESSENGER_SET_FOR_DOMAIN)
        );
        let token_messenger = state::remove_remote_token_messenger(domain);
        event::emit(RemoteTokenMessengerRemoved { domain, token_messenger } );
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    /// Creates a BurnReceipt after validating all parameters.
    /// Does NOT burn the asset or send the message - that happens in complete_burn().
    fun create_burn_receipt(
        caller: &signer,
        asset: FungibleAsset,
        destination_domain: u32,
        mint_recipient: address,
        destination_caller: address,
        max_fee: u64,
        min_finality_threshold: u32,
        hook_data: vector<u8>,
    ): (BurnReceipt, FungibleAsset) {
        // Check if the contract is paused
        pausable::assert_not_paused(state::get_object_address());

        // Check if the caller is denylisted
        denylistable::assert_not_denylisted(signer::address_of(caller));

        let amount = fungible_asset::amount(&asset);
        assert!(amount > 0, error::invalid_argument(EINVALID_AMOUNT));
        assert!(mint_recipient != @0x0, error::invalid_argument(EINVALID_MINT_RECIPIENT_ADDRESS));
        assert!(max_fee < amount, error::invalid_argument(EINVALID_MAX_FEE));

        // Get burn token address from asset metadata
        let metadata = asset.asset_metadata();
        let burn_token = metadata.object_address();

        // Verify minimum fee if minFee > 0
        let min_fee = fee_controller::get_min_fee(burn_token);
        if (min_fee > 0) {
            let min_fee_amount = fee_controller::get_min_fee_amount(amount as u256, burn_token);
            assert!(max_fee >= (min_fee_amount as u64), error::invalid_argument(EINSUFFICIENT_MAX_FEE));
        };

        // Verify the destination domain is supported
        assert!(
            state::is_remote_token_messenger_set_for_domain(destination_domain),
            error::invalid_argument(EUNSUPPORTED_DESTINATION_DOMAIN)
        );

        // Check burn limit
        token_controller::assert_amount_within_burn_limit(burn_token, amount);

        let destination_token_messenger = state::get_remote_token_messenger(destination_domain);

        let receipt = BurnReceipt {
            caller: signer::address_of(caller),
            burn_token,
            amount,
            destination_domain,
            mint_recipient,
            destination_caller,
            destination_token_messenger,
            max_fee,
            min_finality_threshold,
            hook_data,
        };

        (receipt, asset)
    }

    /// Execute `send_message` on local MessageTransmitter using TokenMessengerMinter's signer
    /// Note: In V2, nonce is no longer returned by send_message (it's always 0 on the sending side)
    fun send_deposit_for_burn(
        destination_domain: u32,
        destination_token_messenger: address,
        destination_caller: address,
        min_finality_threshold: u32,
        burn_message: &vector<u8>,
    ) {
        let token_messenger_minter_signer = initializer::get_signer();
        message_transmitter::send_message(
            &token_messenger_minter_signer,
            destination_domain,
            destination_token_messenger,
            destination_caller,
            min_finality_threshold,
            burn_message
        );
    }

    fun validate_remote_token_messenger(domain: u32, token_messenger: address) {
        assert!(
            state::is_remote_token_messenger_set_for_domain(domain),
            error::invalid_argument(ENO_TOKEN_MESSENGER_SET_FOR_DOMAIN)
        );
        assert!(
            state::get_remote_token_messenger(domain) == token_messenger,
            error::permission_denied(ENOT_TOKEN_MESSENGER)
        );
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use std::hash;
    #[test_only]
    use aptos_std::from_bcs;
    #[test_only]
    use std::vector;
    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_framework::resource_account;
    #[test_only]
    use message_transmitter_v2::message;
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;
    #[test_only]
    use std::string::utf8;
    #[test_only]
    use std::option;
    #[test_only]
    use aptos_framework::fungible_asset::MintRef;
    #[test_only]
    use aptos_framework::fungible_asset::BurnRef;
    #[test_only]
    use aptos_framework::fungible_asset::create_test_store;

    // Test Helpers

    #[test_only]
    const REMOTE_DOMAIN: u32 = 4;
    #[test_only]
    const REMOTE_TOKEN_MESSENGER: address = @0xe786e705b98581cbf28488ce4ae116db0918e1f7eb1877d07bf0995cf67724ef;
    #[test_only]
    const REMOTE_STABLECOIN_ADDRESS: address = @0xcafe;
    #[test_only]
    const FEE_RECIPIENT: address = @0xfeed;
    #[test_only]
    const TEST_SEED: vector<u8> = b"test_seed_stablecoin";

    #[test_only]
    struct TestTokenRefs has key  {
        mint_ref: MintRef,
        burn_ref: BurnRef,
    }

    #[test_only]
    const WRONG_TOKEN_SEED: vector<u8> = b"WrongToken";

    #[test_only]
    struct WrongTokenRefs has key {
        mint_ref: MintRef,
    }

    #[test_only]
    fun resource_account_address(): address {
        account::create_resource_address(&@deployer, TEST_SEED)
    }

    #[test_only]
    fun token_address(): address {
        object::create_object_address(&resource_account_address(), b"TestToken")
    }

    #[test_only]
    fun deploy_token_package(): signer {
        if (!account::exists_at(@deployer)) {
            account::create_account_for_test(@deployer);
        };

        // deploy an empty package to a new resource account
        resource_account::create_resource_account(
            &create_signer_for_test(@deployer),
            TEST_SEED,
            b"",
        );

        // compute the resource account address
        let resource_account_address = account::create_resource_address(&@deployer, TEST_SEED);

        // return a resource account signer
        create_signer_for_test(resource_account_address)
    }

    #[test_only]
    fun init_test_token() {
        let resource_acct_signer = deploy_token_package();
        let fa_constructor_ref = object::create_named_object(&resource_acct_signer, b"TestToken");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &fa_constructor_ref,
            option::none(),
            utf8(b"Test Token"),
            utf8(b"TEST"),
            8,
            utf8(b""),
            utf8(b""),
        );

        // store the refs
        let mint_ref = fungible_asset::generate_mint_ref(&fa_constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(&fa_constructor_ref);
        move_to(
            &resource_acct_signer,
            TestTokenRefs {
                mint_ref,
                burn_ref,
            }
        );
    }

    #[test_only]
    public fun get_account_balance(account_address: address): u64 {
        let asset: Object<Metadata> = object::address_to_object(token_address());
        primary_fungible_store::ensure_primary_store_exists(account_address, asset);
        primary_fungible_store::balance(account_address, asset)
    }

    #[test_only]
    public fun init_test_token_messenger_minter(owner: &signer) {
        // Initialize Message Transmitter
        let mt_deployer = create_signer_for_test(@deployer);
        message_transmitter::initialize_test_message_transmitter(&mt_deployer);

        // Initialize Token Messenger Minter
        initializer::initialize_test_token_messenger_minter(1, signer::address_of(owner), FEE_RECIPIENT);

        // Initialize Stablecoin
        init_test_token();

        // Link the newly created FA
        token_controller::test_link_token_pair(
            owner,
            token_address(),
            REMOTE_DOMAIN,
            REMOTE_STABLECOIN_ADDRESS
        );

        // Set Burn Limit
        token_controller::test_set_max_burn_amount_per_message(
            owner,
            token_address(),
            1_000_000
        );

        // Add remote token messenger
        state::add_remote_token_messenger(REMOTE_DOMAIN, REMOTE_TOKEN_MESSENGER);
    }

    #[test_only]
    public fun add_remote_token_messenger_for_testing(domain: u32, token_messenger: address) {
        state::add_remote_token_messenger(domain, token_messenger);
    }

    #[test_only]
    public fun create_mint_receipt_for_testing(receipt: Receipt, local_token: address, mint_recipient: address, amount: u64, fee: u64): MintReceipt {
        MintReceipt {
            receipt,
            local_token,
            mint_recipient,
            amount,
            fee,
        }
    }

    #[test_only]
    public fun create_burn_receipt_for_testing(
        caller: address,
        burn_token: address,
        amount: u64,
        destination_domain: u32,
        mint_recipient: address,
        destination_caller: address,
        destination_token_messenger: address,
        max_fee: u64,
        min_finality_threshold: u32,
        hook_data: vector<u8>): BurnReceipt {
        BurnReceipt {
            caller,
            burn_token,
            amount,
            destination_domain,
            mint_recipient,
            destination_caller,
            destination_token_messenger,
            max_fee,
            min_finality_threshold,
            hook_data,
        }
    }

    #[test_only]
    fun mint_test_token(amount: u64): FungibleAsset {
        let test_token_refs = borrow_global<TestTokenRefs>(resource_account_address());
        test_token_refs.mint_ref.mint(amount)
    }

    #[test_only]
    fun burn_test_token(asset: FungibleAsset) {
        let test_token_refs = borrow_global<TestTokenRefs>(resource_account_address());
        test_token_refs.burn_ref.burn(asset)
    }

    #[test_only]
    public fun mint_test_tokens(owner: &signer, to_address: address, amount: u64) {
        let asset = mint_test_token(amount);
        let token_obj: Object<Metadata> = object::address_to_object(token_address());
        let store = primary_fungible_store::ensure_primary_store_exists(to_address, token_obj);
        dispatchable_fungible_asset::deposit(store, asset);
        let _ = owner;
    }

    #[test_only]
    public fun deposit_test_token(to_address: address, amount: u64) {
        let asset = mint_test_token(amount);
        let token_obj: Object<Metadata> = object::address_to_object(token_address());
        let store = primary_fungible_store::ensure_primary_store_exists(to_address, token_obj);
        dispatchable_fungible_asset::deposit(store, asset);
    }

    #[test_only]
    public fun withdraw_from_primary_store(owner: &signer, amount: u64, burn_token: address): FungibleAsset {
        let token_obj: Object<Metadata> = object::address_to_object(burn_token);
        let store = primary_fungible_store::ensure_primary_store_exists(signer::address_of(owner), token_obj);
        dispatchable_fungible_asset::withdraw(owner, store, amount)
    }

    #[test_only]
    public fun get_signer_balance(account: &signer): u64 {
        let account_address = signer::address_of(account);
        get_account_balance(account_address)
    }

    #[test_only]
    /// Test-only helper to register a handler.
    public fun test_register_handler(owner: &signer, token_address: address, handler_address: address) {
        handler_registry::test_register_handler_for_testing(owner, token_address, handler_address);
    }

    #[test_only]
    /// Test-only helper to deregister a handler.
    public fun test_deregister_handler(owner: &signer, token_address: address) {
        handler_registry::test_deregister_handler_for_testing(owner, token_address);
    }

    #[test_only]
    /// Helper to setup and register a handler for burn operations.
    /// Returns the handler address and signer.
    fun setup_handler_for_burn(owner: &signer, burn_token: address): (address, signer) {
        let handler_address = @0xdead;
        test_register_handler(owner, burn_token, handler_address);
        let handler_signer = create_signer_for_test(handler_address);
        (handler_address, handler_signer)
    }

    #[test_only]
    /// Helper to setup and register a handler for mint operations.
    /// Returns the handler address and signer.
    fun setup_handler_for_mint(owner: &signer, token: address): (address, signer) {
        let handler_address = @0xdead;
        test_register_handler(owner, token, handler_address);
        let handler_signer = create_signer_for_test(handler_address);
        (handler_address, handler_signer)
    }

    #[test_only]
    /// Test-only helper to consume a MintReceipt without completing the full mint flow.
    /// Used by expected_failure tests that need to consume the hot potato.
    public fun test_destroy_mint_receipt(mint_receipt: MintReceipt) {
        let MintReceipt {
            receipt,
            local_token: _,
            mint_recipient: _,
            amount: _,
            fee: _,
        } = mint_receipt;
        // Complete the underlying receipt using the TMM signer (the recipient)
        let tmm_signer = initializer::get_signer_for_testing();
        message_transmitter::complete_receive_message(&tmm_signer, receipt);
    }

    #[test_only]
    fun get_valid_deposit_for_burn_message_and_attestation(): (vector<u8>, vector<u8>) {
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::serialize(
            message_body_version(),
            from_bcs::to_address(hash::sha3_256(b"burn_token")),
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            85720194,
            @deployer,
            0,
            &empty_hook_data
        );
        let original_message = message::serialize(
            0, // version
            9, // source_domain
            REMOTE_DOMAIN, // destination_domain
            signer::address_of(&initializer::get_signer_for_testing()), // sender
            REMOTE_TOKEN_MESSENGER, // recipient
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb, // destination_caller
            0, // min_finality_threshold
            &burn_msg, // message_body
        );
        let original_attestation = x"bb2d94b3e13f83ce6f73d53d1d3c13dece3ad1b8fe0ebc8b92fce71ea3d16b1b0a48ea89eda6a913e04a29a5e9ea50aa0a2f51c21f24d7b2b8b2e5ded6660f091c";
        (original_message, original_attestation)
    }

    #[test_only]
    /// Creates a valid Receipt for testing prepare_mint with amount 8572 and fee executed 0.
    public fun create_test_receipt_for_mint(): Receipt {
        create_test_receipt_for_mint_with_fee(8572, 0)
    }

    #[test_only]
    /// Creates a valid Receipt for testing prepare_mint without needing attestation verification.
    public fun create_test_receipt_for_mint_with_fee(amount: u256, fee_executed: u256): Receipt {
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            amount,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            100,
            fee_executed,
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")), // caller
            tmm_address, // recipient (TMM)
            REMOTE_DOMAIN, // source_domain
            REMOTE_TOKEN_MESSENGER, // sender
            7384, // nonce
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg, // message_body
        )
    }

    #[test_only]
    fun test_deposit_for_burn(owner: &signer, destination_caller: address, hook_data: vector<u8>) {
        init_test_token_messenger_minter(owner);
        deposit_test_token( signer::address_of(owner), 1_000_000);
        let amount = 3482;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let account_balance = get_signer_balance(owner);
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, destination_caller, 100, 1000, hook_data);

        // Register a handler to complete the burn
        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);

        // Burn the asset and complete burn (like a handler would do)
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);

        // Verify event was emitted (nonce is 0 in V2)
        assert_eq(event::was_event_emitted(&DepositForBurn {
            burn_token,
            amount,
            depositor: signer::address_of(owner),
            mint_recipient,
            destination_domain: REMOTE_DOMAIN,
            destination_token_messenger: REMOTE_TOKEN_MESSENGER,
            destination_caller,
            max_fee: 100,
            min_finality_threshold: 1000,
            hook_data,
        }), true);

        // Verify balance decreased by the burn amount
        let expected_account_balance = account_balance - amount;
        assert_eq(get_signer_balance(owner), expected_account_balance);
    }

    #[test_only]
    fun init_wrong_token() {
        let resource_acct_signer = create_signer_for_test(resource_account_address());
        let constructor_ref = object::create_named_object(&resource_acct_signer, WRONG_TOKEN_SEED);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor_ref,
            option::none(),
            utf8(b"Wrong Token"),
            utf8(b"WRONG"),
            8,
            utf8(b""),
            utf8(b""),
        );
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        move_to(
            &resource_acct_signer,
            WrongTokenRefs { mint_ref }
        );
    }

    #[test_only]
    fun mint_wrong_token(amount: u64): FungibleAsset {
        let refs = borrow_global<WrongTokenRefs>(resource_account_address());
        refs.mint_ref.mint(amount)
    }

    #[test_only]
    fun wrong_token_address(): address {
        object::create_object_address(&resource_account_address(), WRONG_TOKEN_SEED)
    }

    // Deposit For Burn Tests

    #[test(owner = @deployer)]
    fun test_deposit_for_burn_success(owner: &signer) {
        test_deposit_for_burn(owner, @0x0, vector::empty<u8>());
    }

    #[test(owner = @deployer)]
    fun test_deposit_for_burn_with_destination_caller_success(owner: &signer) {
        let destination_caller = from_bcs::to_address(hash::sha3_256(b"destination_caller"));
        test_deposit_for_burn(owner, destination_caller, vector::empty<u8>());
    }

    #[test(owner = @deployer)]
    fun test_deposit_for_burn_with_hook_data_success(owner: &signer) {
        let hook_data = x"deadbeef";
        test_deposit_for_burn(owner, @0x0, hook_data);
    }

    #[test(owner = @deployer)]
    fun test_deposit_for_burn_with_destination_caller_and_hook_data_success(owner: &signer) {
        let hook_data = x"deadbeef";
        let destination_caller = from_bcs::to_address(hash::sha3_256(b"destination_caller"));
        test_deposit_for_burn(owner, destination_caller, hook_data);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_deposit_for_burn_with_paused_state(owner: &signer) {
        init_test_token_messenger_minter(owner);
        pausable::set_paused_for_testing(state::get_object_address(), true);
        deposit_test_token( signer::address_of(owner), 1_000_000);
        let amount = 3482;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 100, 1000, vector::empty<u8>());
        // Register a handler to complete the burn
        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10004, location = denylistable)]
    fun test_deposit_for_burn_with_denylisted_state(owner: &signer) {
        init_test_token_messenger_minter(owner);
        denylistable::set_denylisted_for_testing(signer::address_of(owner), true);
        deposit_test_token(signer::address_of(owner), 1_000_000);
        let amount = 3482;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 100, 1000, vector::empty<u8>());
        // Register a handler to complete the burn
        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_deposit_for_burn_invalid_amount(owner: &signer) {
        init_test_token_messenger_minter(owner);
        deposit_test_token(signer::address_of(owner), 1_000_000);
        let amount = 0;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        
        // deposit_for_burn will abort with EINVALID_AMOUNT, so complete_burn is never called
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 0, 0, vector::empty<u8>());

        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_deposit_for_burn_invalid_mint_recipient(owner: &signer) {
        init_test_token_messenger_minter(owner);
        deposit_test_token(signer::address_of(owner), 1_000_000);
        let amount = 51;
        let mint_recipient = @0x0;
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        
        // deposit_for_burn will abort with EINVALID_MINT_RECIPIENT_ADDRESS, so complete_burn is never called
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 0, 0, vector::empty<u8>());

        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_deposit_for_burn_invalid_max_fee(owner: &signer) {
        init_test_token_messenger_minter(owner);
        mint_test_tokens(owner, signer::address_of(owner), 1_000_000);
        let amount = 51;
        let max_fee = 51;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);

        // deposit_for_burn will abort with EINVALID_MAX_FEE, so complete_burn is never called
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, max_fee, 0, vector::empty<u8>());

        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10004, location = Self)]
    fun test_deposit_for_burn_insufficient_max_fee(owner: &signer) {
        init_test_token_messenger_minter(owner);
        deposit_test_token(signer::address_of(owner), 1_000_000);
        let amount = 1_000_000;
        let max_fee = 5;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);

        // set the min fee to 100
        fee_controller::set_min_fee_for_testing(burn_token, 100);

        // deposit_for_burn will abort with EINSUFFICIENT_MAX_FEE, so complete_burn is never called
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, max_fee, 0, vector::empty<u8>());

        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_deposit_for_burn_invalid_destination_domain(owner: &signer) {
        init_test_token_messenger_minter(owner);
        deposit_test_token(signer::address_of(owner), 1_000_000);
        let amount = 51;
        let destination_domain = 3;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        // deposit_for_burn will abort with EUNSUPPORTED_DESTINATION_DOMAIN, so complete_burn is never called
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, destination_domain, mint_recipient, @0x0, 0, 0, vector::empty<u8>());

        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x20003, location = token_controller)]
    fun test_deposit_for_burn_over_burn_limit(owner: &signer) {
        init_test_token_messenger_minter(owner);

        // set the burn limit to 5_000
        token_controller::test_set_max_burn_amount_per_message(owner,token_address(), 5000);

        deposit_test_token(signer::address_of(owner), 1_000_000);
        let amount = 10_000;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        
        // deposit_for_burn will abort with EAMOUNT_EXCEEDS_BURN_LIMIT, so complete_burn is never called
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 0, 0, vector::empty<u8>());

        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x60001, location = handler_registry)]
    fun test_complete_for_burn_unregistered_handler(owner: &signer) {
        init_test_token_messenger_minter(owner);
        deposit_test_token(signer::address_of(owner), 1_000_000);

        let amount = 10_000;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 0, 0, vector::empty<u8>());

        let handler_address = @0xdead;
        let handler_signer = create_signer_for_test(handler_address);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50002, location = handler_registry)]
    fun test_complete_for_burn_invalid_signature(owner: &signer) {
        init_test_token_messenger_minter(owner);
        deposit_test_token(signer::address_of(owner), 1_000_000);

        let amount = 10_000;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 0, 0, vector::empty<u8>());

        let handler_address = @0xdead;

        // register a handler with an invalid signature
        test_register_handler(owner, burn_token, @0x1234);
        let handler_signer = create_signer_for_test(handler_address);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    // Add/Remove TokenMessenger Tests

    #[test(owner = @deployer)]
    fun test_add_remote_token_messenger(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"new_token_messenger"));
        add_remote_token_messenger(owner, domain, token_messenger);
        assert!(event::was_event_emitted(&RemoteTokenMessengerAdded { domain, token_messenger }), 0);
    }

    #[test(owner = @deployer, not_owner = @0xfaa)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_add_remote_token_messenger_not_owner(owner: &signer, not_owner: &signer) {
        init_test_token_messenger_minter(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"token_messenger"));
        add_remote_token_messenger(not_owner, domain, token_messenger);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x80005, location = Self)]
    fun test_add_remote_token_messenger_already_set(owner: &signer) {
        init_test_token_messenger_minter(owner);
        assert!(state::is_remote_token_messenger_set_for_domain(REMOTE_DOMAIN), 0);
        add_remote_token_messenger(owner, REMOTE_DOMAIN, REMOTE_TOKEN_MESSENGER);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000b, location = Self)]
    fun test_add_remote_token_messenger_zero_address(owner: &signer) {
        init_test_token_messenger_minter(owner);
        add_remote_token_messenger(owner, 7, @0x0);
    }

    #[test(owner = @deployer)]
    fun test_remove_remote_token_messenger(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"token_messenger"));
        state::add_remote_token_messenger(domain, token_messenger);
        remove_remote_token_messenger(owner, domain);
        assert!(event::was_event_emitted(&RemoteTokenMessengerRemoved{ domain, token_messenger }), 0);
    }

    #[test(owner = @deployer, not_owner = @0xfaa)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_remove_remote_token_messenger_not_owner(owner: &signer, not_owner: &signer) {
        init_test_token_messenger_minter(owner);
        let domain = 7;
        let token_messenger = from_bcs::to_address(hash::sha3_256(b"token_messenger"));
        state::add_remote_token_messenger(domain, token_messenger);
        remove_remote_token_messenger(not_owner, domain);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_remove_remote_token_messenger_none_set(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let remote_domain = 15;
        assert!(!state::is_remote_token_messenger_set_for_domain(remote_domain), 0);
        remove_remote_token_messenger(owner, remote_domain);
    }

    // prepare_mint / complete_mint Tests

    #[test(owner = @deployer)]
    fun test_prepare_mint_success(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let receipt = create_test_receipt_for_mint();
        let mint_receipt = prepare_mint(receipt);
        let (local_token, mint_recipient, amount, fee) = get_mint_details(&mint_receipt);
        assert_eq(local_token, token_address());
        assert_eq(mint_recipient, from_bcs::to_address(hash::sha3_256(b"mint_recipient")));
        assert_eq(amount, 8572);
        assert_eq(fee, 0);

        // Register a handler to complete the mint
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, token_address());

        // Create a mock asset and complete mint
        let asset = mint_test_token(amount);
        let token_metadata: object::Object<Metadata> = object::address_to_object(local_token);
        let fee_asset = fungible_asset::zero(token_metadata);
        complete_mint(&handler_signer, mint_receipt, asset, fee_asset);

        assert_eq(event::was_event_emitted(&MintAndWithdraw {
            mint_token: token_address(),
            mint_recipient,
            amount: amount as u64,
            fee_collected: 0,
        }), true);
        assert_eq(get_account_balance(mint_recipient), amount);
    }

    #[test(owner = @deployer)]
    fun test_prepare_mint_success_with_fee(owner: &signer) {
        init_test_token_messenger_minter(owner);
        // amount 8572, fee executed 10
        let receipt = create_test_receipt_for_mint_with_fee(8572, 10);
        let mint_receipt = prepare_mint(receipt);
        let (local_token, mint_recipient, amount, fee) = get_mint_details(&mint_receipt);
        assert_eq(local_token, token_address());
        assert_eq(mint_recipient, from_bcs::to_address(hash::sha3_256(b"mint_recipient")));
        // amount in MintReceipt is (burn_amount - fee) = 8572 - 10 = 8562
        assert_eq(amount, 8562);
        assert_eq(fee, 10);

        // Register a handler to complete the mint
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, token_address());

        // Create a mock asset and complete mint
        let asset = mint_test_token(amount);
        let fee_asset = mint_test_token(fee);
        complete_mint(&handler_signer, mint_receipt, asset, fee_asset);

        assert_eq(event::was_event_emitted(&MintAndWithdraw {
            mint_token: token_address(),
            mint_recipient,
            amount,
            fee_collected: fee as u64,
        }), true);
        assert_eq(get_account_balance(mint_recipient), amount);
        assert_eq(get_account_balance(fee_controller::get_fee_recipient()), fee);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_prepare_mint_paused_state(owner: &signer) {
        init_test_token_messenger_minter(owner);

        // pause the contract
        pausable::set_paused_for_testing(state::get_object_address(), true);

        let receipt = create_test_receipt_for_mint();

        // prepare_mint will abort with EINVALID_MESSAGE_BODY_VERSION, so this is never called
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    fun test_prepare_mint_invalid_recipient(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            8572,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        // Create receipt with wrong recipient (not TMM address)
        let wrong_recipient = @0xbeef;
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            wrong_recipient, // Wrong recipient - not TMM
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50007, location = Self)]
    fun test_prepare_mint_wrong_remote_token_messenger(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            8572,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        // Use a wrong sender that doesn't match the registered REMOTE_TOKEN_MESSENGER
        let wrong_token_messenger = @0xdeadbeef;
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            wrong_token_messenger, // Wrong sender - not the registered token messenger
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10008, location = Self)]
    fun test_prepare_mint_invalid_version(owner: &signer) {
        init_test_token_messenger_minter(owner);
        // Create receipt with version 1 (current version)
        let receipt = create_test_receipt_for_mint();
        // Change state version to 2 - now the burn_message version (1) won't match
        state::set_message_body_version(2);
        // prepare_mint will abort with EINVALID_MESSAGE_BODY_VERSION, so this is never called
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_prepare_mint_no_remote_token_messenger(owner: &signer) {
        init_test_token_messenger_minter(owner);
        state::remove_remote_token_messenger(REMOTE_DOMAIN);
        let receipt = create_test_receipt_for_mint();
        // prepare_mint will abort with ENO_TOKEN_MESSENGER_SET_FOR_DOMAIN, so this is never called
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    fun test_prepare_mint_finality_threshold_at_minimum(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let receipt = create_test_receipt_for_mint();
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10012, location = Self)]
    fun test_prepare_mint_finality_threshold_below_minimum(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            8572,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED - 1, // below minimum
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer, aptos_framework = @0x1)]
    fun test_prepare_mint_with_expiration_block(owner: &signer, aptos_framework: &signer) {
        // Initialize framework account and block module
        // Note: block::get_current_block_height() returns 0 in unit tests,
        // so this test validates that a message with expiration_block = 1 is NOT expired (1 > 0)
        account::create_account_for_test(signer::address_of(aptos_framework));
        block::initialize_for_test(aptos_framework, 1);

        init_test_token_messenger_minter(owner);
        
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            8572,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            0,
            1,  // expiration_block = 1 (not expired since current_block = 0 in tests, 1 > 0)
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());

        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_prepare_mint_amount_exceeds_max_u64(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        // Create burn message with amount > MAX_U64
        let amount_exceeds_max: u256 = 18_446_744_073_709_551_616; // MAX_U64 + 1
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            amount_exceeds_max,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000d, location = Self)]
    fun test_prepare_mint_invalid_fee(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            1000,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            1000,
            1000, // fee excuted equals to amount
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000e, location = Self)]
    fun test_prepare_mint_exceeds_max_fee(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            1000,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            100,
            101, // fee excuted exceeds max fee
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        test_destroy_mint_receipt(mint_receipt);
    }

    // complete_mint Tests

    #[test(owner = @deployer)]
    fun test_complete_mint_success(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        // Create burn message with zero amount
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            1000, // Zero amount
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            100,
            100,
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        let (local_token, mint_recipient, amount, fee) = get_mint_details(&mint_receipt);
        // amount in MintReceipt is (burn_amount - fee) = 1000 - 100 = 900
        assert_eq(amount, 900);
        assert_eq(fee, 100);

        // Register handler and complete mint with zero asset
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, local_token);

        let asset = mint_test_token(amount);
        let fee_asset = mint_test_token(fee);
        complete_mint(&handler_signer, mint_receipt, asset, fee_asset);

        assert!(event::was_event_emitted(&MintAndWithdraw {
            mint_token: token_address(),
            mint_recipient,
            amount: amount as u64,
            fee_collected: fee as u64,
        }), 0);
    }

    #[test(owner = @deployer)]
    fun test_complete_mint_zero_amount(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        // Create burn message with zero amount
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            0, // Zero amount
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        let (local_token, mint_recipient, amount, _fee) = get_mint_details(&mint_receipt);
        assert_eq(amount, 0);

        // Register handler and complete mint with zero asset
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, local_token);
        // Create zero asset using fungible_asset::zero instead of minting
        let token_obj = object::address_to_object<Metadata>(local_token);
        let asset = fungible_asset::zero(token_obj);
        complete_mint(&handler_signer, mint_receipt, asset, fungible_asset::zero(token_obj));

        assert!(event::was_event_emitted(&MintAndWithdraw {
            mint_token: token_address(),
            mint_recipient,
            amount: 0,
            fee_collected: 0,
        }), 0);
    }

    #[test(owner = @deployer)]
    fun test_complete_mint_to_existing_store(owner: &signer) {
        init_test_token_messenger_minter(owner);

        // Create a secondary store for the mint recipient first
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let token_obj: Object<Metadata> = object::address_to_object(token_address());

        // Create a secondary store for this recipient
        let store = primary_fungible_store::ensure_primary_store_exists(mint_recipient, token_obj);
        let store_address = store.object_address();

        // Create a receipt that will mint to the store address directly
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            store_address, // Mint directly to the store address
            5000,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7385,
            MIN_FINALITY_THRESHOLD_EXECUTED, // finality_threshold_executed
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);

        // Register handler and complete mint
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, token_address());
        let asset = mint_test_token(5000);
        complete_mint(&handler_signer, mint_receipt, asset, fungible_asset::zero(token_obj));

        assert!(event::was_event_emitted(&MintAndWithdraw {
            mint_token: token_address(),
            mint_recipient: store_address,
            amount: 5000,
            fee_collected: 0,
        }), 0);
    }

    #[test(owner = @deployer, user = @0xfaa)]
    fun test_complete_mint_to_secondary_store_success(owner: &signer, user: &signer) {
        init_test_token_messenger_minter(owner);

        // Create a secondary store for the CORRECT token owned by user
        let token_obj: Object<Metadata> = object::address_to_object(token_address());
        let secondary_store = create_test_store(user, token_obj);
        let secondary_store_address = secondary_store.object_address();
        assert_eq(fungible_asset::balance(secondary_store), 0);

        // Use the secondary store's address as mint_recipient
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            secondary_store_address,
            5000,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7388,
            MIN_FINALITY_THRESHOLD_EXECUTED,
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);

        // Register handler and complete mint
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, token_address());
        let asset = mint_test_token(5000);
        complete_mint(&handler_signer, mint_receipt, asset, fungible_asset::zero(token_obj));

        // Tokens should be deposited directly into the secondary store
        assert_eq(fungible_asset::balance(secondary_store), 5000);
    }

    #[test(owner = @deployer, user = @0xfaa)]
    #[expected_failure(abort_code = 0x10013, location = Self)]
    fun test_complete_mint_wrong_token_store_aborts(owner: &signer, user: &signer) {
        init_test_token_messenger_minter(owner);
        init_wrong_token();

        // Create a secondary store for the WRONG token owned by user
        let wrong_metadata: Object<Metadata> = object::address_to_object(wrong_token_address());
        let wrong_store = create_test_store(user, wrong_metadata);
        let wrong_store_address = wrong_store.object_address();

        // Use the wrong store's address as mint_recipient
        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::serialize(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            wrong_store_address,
            5000,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7386,
            MIN_FINALITY_THRESHOLD_EXECUTED,
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);

        // Register handler and complete mint -- should abort with EASSET_METADATA_MISMATCH
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, token_address());
        let token_obj: Object<Metadata> = object::address_to_object(token_address());
        let asset = mint_test_token(5000);
        complete_mint(&handler_signer, mint_receipt, asset, fungible_asset::zero(token_obj));
    }

    #[test(owner = @deployer, user = @0xfaa)]
    #[expected_failure(abort_code = 0x10013, location = Self)]
    fun test_complete_mint_fee_to_wrong_token_store_aborts(owner: &signer, user: &signer) {
        init_test_token_messenger_minter(owner);
        init_wrong_token();

        // Create a wrong-token store at the fee_recipient address
        let wrong_metadata: Object<Metadata> = object::address_to_object(wrong_token_address());
        let wrong_store = create_test_store(user, wrong_metadata);
        let wrong_store_address = wrong_store.object_address();

        // Override fee recipient to the wrong store address
        fee_controller::set_fee_recipient_for_testing(wrong_store_address);

        let empty_hook_data = vector::empty<u8>();
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            1000,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            100,
            100,
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7387,
            MIN_FINALITY_THRESHOLD_EXECUTED,
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        let (local_token, _mint_recipient, amount, fee) = get_mint_details(&mint_receipt);
        assert_eq(amount, 900);
        assert_eq(fee, 100);

        // Register handler and complete mint -- should abort with EASSET_METADATA_MISMATCH
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, local_token);
        let asset = mint_test_token(amount);
        let fee_asset = mint_test_token(fee);
        complete_mint(&handler_signer, mint_receipt, asset, fee_asset);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_complete_mint_invalid_amount(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        // Create burn message with invalid amount
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            100,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            50,
            10,
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED,
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        let (local_token, _mint_recipient, amount, fee) = get_mint_details(&mint_receipt);
        // amount in MintReceipt is (burn_amount - fee) = 100 - 10 = 90
        assert_eq(amount, 90);
        assert_eq(fee, 10);

        // Register handler
        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, local_token);

        // Mint 50 tokens for the asset, which is less than the amount in the mint receipt (90)
        let asset = mint_test_token(50);
        let fee_asset = mint_test_token(fee);
        complete_mint(&handler_signer, mint_receipt, asset, fee_asset);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000f, location = Self)]
    fun test_complete_mint_invalid_fee(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let empty_hook_data = vector::empty<u8>();
        // Create burn message with invalid fee
        let burn_msg = burn_message::build_message_for_test(
            message_body_version(),
            REMOTE_STABLECOIN_ADDRESS,
            from_bcs::to_address(hash::sha3_256(b"mint_recipient")),
            100,
            from_bcs::to_address(hash::sha3_256(b"sender_address")),
            50,
            10,
            0,
            &empty_hook_data
        );
        let tmm_address = signer::address_of(&initializer::get_signer_for_testing());
        let receipt = message_transmitter::create_receipt_for_testing(
            from_bcs::to_address(hash::sha3_256(b"destination_caller")),
            tmm_address,
            REMOTE_DOMAIN,
            REMOTE_TOKEN_MESSENGER,
            7384,
            MIN_FINALITY_THRESHOLD_EXECUTED,
            burn_msg,
        );
        let mint_receipt = prepare_mint(receipt);
        let (local_token, _mint_recipient, amount, fee) = get_mint_details(&mint_receipt);
        // amount in MintReceipt is (burn_amount - fee) = 100 - 10 = 90
        assert_eq(amount, 90);
        assert_eq(fee, 10);

        // Register handler and complete mint with invalid fee
        let handler_address = @0xdead;
        test_register_handler(owner, local_token, handler_address);
        let handler_signer = create_signer_for_test(handler_address);

        let asset = mint_test_token(amount);

        // Mint 1 token for the fee, which is less than the fee in the mint receipt
        let fee_asset = mint_test_token(1);
        complete_mint(&handler_signer, mint_receipt, asset, fee_asset);
    }

    // get_signer_for_handler Tests

    #[test(owner = @deployer)]
    fun test_get_signer_for_handler_success(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let handler_address = @0xdead;
        let token_address = token_address();

        // Register handler
        test_register_handler(owner, token_address, handler_address);

        // Get minter signer
        let handler_signer = create_signer_for_test(handler_address);
        let minter_signer = get_signer_for_handler(&handler_signer, token_address);

        // Verify we got the TMM signer
        assert_eq(signer::address_of(&minter_signer), state::get_object_address());
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x60001, location = handler_registry)]
    fun test_get_signer_for_handler_not_registered(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let handler_signer = create_signer_for_test(@0xdead);
        get_signer_for_handler(&handler_signer, token_address());
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50002, location = handler_registry)]
    fun test_get_signer_for_handler_wrong_handler(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let token_address = token_address();

        // Register handler1
        test_register_handler(owner, token_address, @0xdead1);

        // Try to get signer with handler2
        let wrong_handler_signer = create_signer_for_test(@0xdead2);
        get_signer_for_handler(&wrong_handler_signer, token_address);
    }

    // View Function Tests

    #[test(owner = @deployer)]
    fun test_view_message_body_version(owner: &signer) {
        init_test_token_messenger_minter(owner);
        assert_eq(message_body_version(), state::get_message_body_version());
    }

    #[test(owner = @deployer)]
    fun test_view_remote_token_messenger(owner: &signer) {
        init_test_token_messenger_minter(owner);
        assert_eq(state::get_remote_token_messenger(REMOTE_DOMAIN), remote_token_messenger(REMOTE_DOMAIN));
    }

    #[test(owner = @deployer)]
    fun test_view_num_remote_token_messengers(owner: &signer) {
        init_test_token_messenger_minter(owner);
        assert_eq(state::get_num_remote_token_messengers(), num_remote_token_messengers());
    }

    #[test(owner = @deployer)]
    fun test_view_max_burn_amount_per_message(owner: &signer) {
        init_test_token_messenger_minter(owner);
        let (_, max_burn_amount) = state::get_max_burn_limit_per_message_for_token(token_address());
        assert_eq(max_burn_amount_per_message(token_address()), max_burn_amount);
    }

    // Additional tests for uncovered lines

    #[test(owner = @deployer)]
    fun test_get_burn_details(owner: &signer) {
        init_test_token_messenger_minter(owner);
        mint_test_tokens(owner, signer::address_of(owner), 1_000_000);
        let amount = 5000;
        let mint_recipient = from_bcs::to_address(hash::sha3_256(b"mint_recipient"));
        let burn_token = token_address();
        let asset = withdraw_from_primary_store(owner, amount, burn_token);
        let (burn_receipt, asset) = deposit_for_burn(owner, asset, REMOTE_DOMAIN, mint_recipient, @0x0, 0, 0, vector::empty<u8>());

        // Test get_burn_details
        let (returned_burn_token, returned_amount, returned_mint_recipient) = get_burn_details(&burn_receipt);
        assert_eq(returned_burn_token, burn_token);
        assert_eq(returned_amount, amount);
        assert_eq(returned_mint_recipient, mint_recipient);

        // Clean up - register handler and complete burn
        let (_handler_address, handler_signer) = setup_handler_for_burn(owner, burn_token);
        burn_test_token(asset);
        complete_burn(&handler_signer, burn_receipt);
    }

    // Asset Metadata Validation Tests

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10010, location = Self)]
    fun test_complete_mint_invalid_asset_metadata(owner: &signer) {
        init_test_token_messenger_minter(owner);
        init_wrong_token();

        let receipt = create_test_receipt_for_mint();
        let mint_receipt = prepare_mint(receipt);
        let (local_token, _mint_recipient, amount, _fee) = get_mint_details(&mint_receipt);

        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, local_token);

        let wrong_asset = mint_wrong_token(amount);
        let token_obj = object::address_to_object<Metadata>(local_token);
        let fee_asset = fungible_asset::zero(token_obj);
        complete_mint(&handler_signer, mint_receipt, wrong_asset, fee_asset);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10011, location = Self)]
    fun test_complete_mint_invalid_fee_asset_metadata(owner: &signer) {
        init_test_token_messenger_minter(owner);
        init_wrong_token();

        let receipt = create_test_receipt_for_mint_with_fee(8572, 10);
        let mint_receipt = prepare_mint(receipt);
        let (local_token, _mint_recipient, amount, fee) = get_mint_details(&mint_receipt);

        let (_handler_address, handler_signer) = setup_handler_for_mint(owner, local_token);

        let asset = mint_test_token(amount);
        let wrong_fee_asset = mint_wrong_token(fee);
        complete_mint(&handler_signer, mint_receipt, asset, wrong_fee_asset);
    }
}
