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

/// Handler for stablecoin (USDC, EURC, etc.) in the multi-token CCTP architecture.
/// This handler is registered with the token_messenger_minter and handles
/// minting and burning of stablecoin tokens for cross-chain transfers.
module stablecoin_handler::handler {
    // Built-in Modules
    use std::error;
    use aptos_framework::object;
    use aptos_framework::resource_account;
    use aptos_framework::fungible_asset::{Self, Metadata, FungibleAsset};
    use aptos_extensions::upgradable;
    use aptos_extensions::manageable;

    // Stablecoin Modules
    use stablecoin::treasury;
    use stablecoin::stablecoin::stablecoin_address;

    // Token Messenger Minter Modules
    use token_messenger_minter_v2::token_messenger_minter::{Self, MintReceipt, BurnReceipt};

    // Constants
    const HANDLER_SEED: vector<u8> = b"StablecoinHandler";

    // Errors
    const EWRONG_TOKEN: u64 = 1;
    const EAMOUNT_MISMATCH: u64 = 2;

    // -----------------------------
    // ----------- State -----------
    // -----------------------------

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct HandlerState has key {
        extend_ref: object::ExtendRef,
    }

    // -----------------------------
    // ------ Initialization -------
    // -----------------------------

    fun init_module(resource_acct_signer: &signer) {
        // Create handler named object
        let constructor_ref = object::create_named_object(resource_acct_signer, HANDLER_SEED);
        let handler_signer = &constructor_ref.generate_signer();
        let extend_ref = constructor_ref.generate_extend_ref();

        move_to(handler_signer, HandlerState { extend_ref });

        // Setup upgradeability
        let signer_cap = resource_account::retrieve_resource_account_cap(resource_acct_signer, @deployer);
        manageable::new(resource_acct_signer, @deployer);
        upgradable::new(resource_acct_signer, signer_cap);
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    /// Returns the handler's object address
    public fun handler_address(): address {
        object::create_object_address(&@stablecoin_handler, HANDLER_SEED)
    }

    #[view]
    /// Returns the token address this handler supports
    public fun supported_token(): address {
        stablecoin_address()
    }

    // -----------------------------
    // ----- Public Functions ------
    // -----------------------------

    /// Called to handle stablecoin minting for cross-chain transfers.
    /// This function:
    /// 1. Extracts mint details (local_token, amount and fee) from the MintReceipt
    /// 2. Verifies the local token matches the stablecoin
    /// 3. Gets the TMM signer via token_messenger_minter
    /// 4. Mints tokens and fee using the stablecoin treasury
    /// 5. Calls complete_mint which deposits tokens, deposits fees, emits event, destroys Receipt
    ///
    /// Aborts if:
    /// - local_token does not match stablecoin_address (EWRONG_TOKEN)
    /// - token_messenger_minter::get_signer_for_handler aborts (handler not registered)
    /// - treasury::mint aborts (not a minter, insufficient allowance)
    /// - token_messenger_minter::complete_mint aborts
    public fun mint(mint_receipt: MintReceipt) {
        // Get mint details from the MintReceipt
        let (local_token, _mint_recipient, amount, fee) = 
            token_messenger_minter::get_mint_details(&mint_receipt);

        // Verify this handler only handles stablecoin
        assert!(
            local_token == stablecoin_address(),
            error::invalid_argument(EWRONG_TOKEN)
        );

        // Get handler identity signer
        let handler_signer = get_handler_signer();

        // Get TMM signer (verifies we're registered in handler_registry)
        let tmm_signer = token_messenger_minter::get_signer_for_handler(&handler_signer, local_token);

        let token_metadata: object::Object<Metadata> = object::address_to_object(local_token);

        // Mint tokens
        let asset = if (amount > 0) {
            treasury::mint(&tmm_signer, amount)
        } else {
            fungible_asset::zero(token_metadata)
        };

        // Mint fee tokens
        let fee_asset = if (fee > 0) {
            treasury::mint(&tmm_signer, fee)
        } else {
            fungible_asset::zero(token_metadata)
        };

        // Complete mint: deposits tokens, emits event, destroys Receipt
        token_messenger_minter::complete_mint(&handler_signer, mint_receipt, asset, fee_asset);
    }

    /// Called to handle stablecoin burning for cross-chain transfers.
    /// This function:
    /// 1. Extracts burn details from the BurnReceipt
    /// 2. Verifies the burn token matches the stablecoin
    /// 3. Verifies the asset amount matches the receipt amount
    /// 4. Gets the TMM signer via token_messenger_minter
    /// 5. Burns tokens using the stablecoin treasury
    /// 6. Calls complete_burn which sends message, emits event, destroys BurnReceipt
    ///
    /// Note: In V2, nonce is no longer returned (it's always 0 on the sending side)
    ///
    /// Aborts if:
    /// - burn_token does not match stablecoin_address (EWRONG_TOKEN)
    /// - asset metadata does not match burn_token from receipt (EWRONG_TOKEN)
    /// - asset amount does not match receipt amount (EAMOUNT_MISMATCH)
    /// - token_messenger_minter::get_signer_for_handler aborts (handler not registered)
    /// - treasury::burn aborts (not a burner)
    /// - token_messenger_minter::complete_burn aborts
    public fun burn(
        burn_receipt: BurnReceipt,
        asset: FungibleAsset,
    ) {
        // Get burn details from the BurnReceipt
        let (burn_token, amount, _mint_recipient) = 
            token_messenger_minter::get_burn_details(&burn_receipt);

        // Verify this handler only handles stablecoin
        assert!(
            burn_token == stablecoin_address(),
            error::invalid_argument(EWRONG_TOKEN)
        );

        // Verify the asset metadata matches the burn_token from receipt
        // This prevents attacks where a different token is passed than what was receipted
        let asset_metadata = asset.asset_metadata();
        assert!(
            asset_metadata.object_address() == burn_token,
            error::invalid_argument(EWRONG_TOKEN)
        );

        // Verify amount matches
        assert!(
            fungible_asset::amount(&asset) == amount,
            error::invalid_argument(EAMOUNT_MISMATCH)
        );

        // Get handler identity signer
        let handler_signer = get_handler_signer();

        // Get TMM signer (verifies we're registered in handler_registry)
        let tmm_signer = token_messenger_minter::get_signer_for_handler(&handler_signer, burn_token);

        // Burn tokens
        treasury::burn(&tmm_signer, asset);

        // Complete burn: sends message, emits event, destroys BurnReceipt
        token_messenger_minter::complete_burn(&handler_signer, burn_receipt);
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    fun get_handler_signer(): signer {
        let handler_addr = handler_address();
        let state = borrow_global<HandlerState>(handler_addr);
        state.extend_ref.generate_signer_for_extending()
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    // Standard Library
    #[test_only]
    use std::option;
    #[test_only]
    use std::signer;
    #[test_only]
    use std::string;
    #[test_only]
    use std::string::utf8;
    #[test_only]
    use std::vector;

    // Aptos Framework
    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_framework::primary_fungible_store;

    // Aptos Extensions
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;

    // Stablecoin
    #[test_only]
    use stablecoin::stablecoin;

    // Token Messenger Minter V2
    #[test_only]
    use token_messenger_minter_v2::initializer;
    #[test_only]
    use token_messenger_minter_v2::token_controller;
    #[test_only]
    use token_messenger_minter_v2::handler_registry;

    // Message Transmitter V2
    #[test_only]
    use message_transmitter_v2::message_transmitter;

    // Test Constants
    #[test_only]
    const TEST_SEED: vector<u8> = b"test_seed_stablecoin";
    #[test_only]
    const TEST_REMOTE_DOMAIN: u32 = 4;
    #[test_only]
    const TEST_REMOTE_TOKEN_MESSENGER: address = @0xe786e705b98581cbf28488ce4ae116db0918e1f7eb1877d07bf0995cf67724ef;
    #[test_only]
    const TEST_REMOTE_TOKEN: address = @0xcafe;
    #[test_only]
    const TEST_MINT_ALLOWANCE: u64 = 100_000_000;
    #[test_only]
    const TEST_BURN_LIMIT: u64 = 1_000_000;
    #[test_only]
    const TEST_FEE_RECIPIENT: address = @0xfeed;

    #[test_only]
    fun deploy_stablecoin_package(): signer {
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

        // verify the resource account address is the same as the configured test package address
        assert_eq(@stablecoin, resource_account_address);

        // return a resource account signer
        create_signer_for_test(resource_account_address)
    }

    #[test_only]
    fun init_test_stablecoin() {
        let resource_acct_signer = deploy_stablecoin_package();
        stablecoin::test_init_module(&resource_acct_signer);
        stablecoin::test_initialize_v1(
            &create_signer_for_test(@deployer),
            string::utf8(b"USDC"),
            string::utf8(b"USDC"),
            6,
            string::utf8(b"icon uri"),
            string::utf8(b"project uri")
        );
    }

    #[test_only]
    /// Test helper to properly initialize the handler module
    /// This sets up the resource account structure that init_module expects
    /// Returns the address where the handler object was created
    fun test_init_handler_module(): address {
        // 1. Create deployer account if needed
        if (!account::exists_at(@deployer)) {
            account::create_account_for_test(@deployer);
        };
        
        // 2. Create a resource account from @deployer with a test seed
        // This creates the resource account and stores the SignerCapability
        let test_seed = b"handler_test_seed";
        
        resource_account::create_resource_account(
            &create_signer_for_test(@deployer),
            test_seed,
            vector::empty() // empty capabilities
        );
        
        // 3. Get the resource account signer
        let resource_account_address = account::create_resource_address(&@deployer, test_seed);
        let resource_account_signer = create_signer_for_test(resource_account_address);
        
        // 4. Now call init_module with the resource account signer
        // This will:
        // - Create the handler named object using HANDLER_SEED
        // - Retrieve the resource account capability (stored in step 2)
        // - Set up manageable and upgradable modules
        init_module(&resource_account_signer);
        
        // 5. Return the computed handler object address
        // The handler object is created at: object_address(resource_account_address, HANDLER_SEED)
        object::create_object_address(&resource_account_address, HANDLER_SEED)
    }

    #[test_only]
    /// Simplified initialization for tests that don't need full init_module complexity
    /// This bypasses the resource_account setup which is deployment-specific
    fun init_test_handler_state() {
        // Create a named object at the expected handler address
        // Note: We use @stablecoin_handler as the creator so the computed address matches handler_address()
        let handler_creator = create_signer_for_test(@stablecoin_handler);
        let constructor_ref = object::create_named_object(&handler_creator, HANDLER_SEED);
        let handler_signer = constructor_ref.generate_signer();
        let extend_ref = constructor_ref.generate_extend_ref();
        
        // Initialize the handler state
        move_to(&handler_signer, HandlerState { extend_ref });
        
        // The computed address should match handler_address()
        let expected = handler_address();
        let actual = constructor_ref.address_from_constructor_ref();
        assert!(expected == actual, 0);
    }

    // -----------------------------
    // ------ Test Helpers ---------
    // -----------------------------

    #[test_only]
    /// Mints stablecoin tokens directly from the treasury for testing purposes.
    /// 
    /// # Prerequisites
    /// * `init_test_handler_and_tmm()` must be called first to:
    ///   - Initialize the stablecoin
    ///   - Configure TMM signer as a minter
    ///   - Set up appropriate mint allowances
    /// 
    /// # Arguments
    /// * `to_address` - Address to receive the minted tokens
    /// * `amount` - Amount of tokens to mint
    fun mint_stablecoin_for_testing(to_address: address, amount: u64) {
        let tmm_signer = initializer::get_signer_for_testing();
        
        // Mint tokens
        let asset = treasury::mint(&tmm_signer, amount);
        // Deposit to primary store (handles store creation automatically)
        primary_fungible_store::deposit(to_address, asset);
    }

    #[test_only]
    /// Initializes the complete test environment including stablecoin, TMM, and handler.
    /// 
    /// This function sets up:
    /// 1. Stablecoin with treasury
    /// 2. Message Transmitter
    /// 3. Token Messenger Minter
    /// 4. TMM as stablecoin minter (with 100M allowance)
    /// 5. Remote token messenger (domain 4)
    /// 6. Token pair linking for cross-chain transfers
    /// 7. Burn limits (1M per message)
    /// 8. Handler state and registration
    /// 
    /// # Returns
    /// The owner signer for use in tests
    fun init_test_handler_and_tmm(): signer {
        // Initialize stablecoin first
        init_test_stablecoin();
        
        // Initialize TMM (without reinitializing stablecoin)
        let owner = create_signer_for_test(@deployer);
        let mt_deployer = create_signer_for_test(@deployer);
        message_transmitter::initialize_test_message_transmitter(&mt_deployer);
        initializer::initialize_test_token_messenger_minter(1, signer::address_of(&owner), TEST_FEE_RECIPIENT);

        // Configure TMM signer as a minter for stablecoin
        let tmm_signer = initializer::get_signer_for_testing();
        treasury::test_configure_controller(&owner, signer::address_of(&tmm_signer), signer::address_of(&tmm_signer));
        treasury::test_configure_minter(&tmm_signer, TEST_MINT_ALLOWANCE);

        // Add remote token messenger (needed for prepare_mint)
        token_messenger_minter::add_remote_token_messenger_for_testing(
            TEST_REMOTE_DOMAIN,
            TEST_REMOTE_TOKEN_MESSENGER
        );

        // Link stablecoin token pair and set burn limit (needed for deposit_for_burn)
        token_controller::test_link_token_pair(&owner, stablecoin_address(), TEST_REMOTE_DOMAIN, TEST_REMOTE_TOKEN);
        token_controller::test_set_max_burn_amount_per_message(&owner, stablecoin_address(), TEST_BURN_LIMIT);

        // Initialize handler state for testing
        init_test_handler_state();
        
        // Register handler with TMM
        token_messenger_minter::test_register_handler(&owner, stablecoin_address(), handler_address());

        owner
    }

    // -----------------------------
    // ---- Initialization Tests ---
    // -----------------------------

    #[test]
    fun test_init_module() {
        // Initialize the handler module and get the handler object address
        let handler_addr = test_init_handler_module();
        
        // Verify HandlerState was created at the computed address
        assert!(exists<HandlerState>(handler_addr), 0);
        
        // Verify the handler object exists
        assert!(object::object_exists<HandlerState>(handler_addr), 1);
    }

    // -----------------------------
    // ------- Mint Tests ----------
    // -----------------------------

    #[test]
    fun test_mint_success() {
        init_test_handler_and_tmm();
        let receipt = token_messenger_minter::create_test_receipt_for_mint();
        let mint_receipt = token_messenger_minter::prepare_mint(receipt);
        mint(mint_receipt);
    }

    #[test]
    fun test_mint_with_fee() {
        init_test_handler_and_tmm();
        let receipt = token_messenger_minter::create_test_receipt_for_mint();
        let mint_receipt = token_messenger_minter::create_mint_receipt_for_testing(
            receipt, 
            stablecoin_address(), 
            @0xDEADBEEF, 
            1000, 
            100);
        mint(mint_receipt);
    }

    #[test]
    fun test_mint_zero_amount() {
        init_test_handler_and_tmm();
        let receipt = token_messenger_minter::create_test_receipt_for_mint();
        let mint_receipt = token_messenger_minter::create_mint_receipt_for_testing(
            receipt, 
            stablecoin_address(), 
            @0xDEADBEEF, 
            0, 
            0);
        mint(mint_receipt);
    }

    #[test]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_mint_with_wrong_token() {
        init_test_handler_and_tmm();
        let receipt = token_messenger_minter::create_test_receipt_for_mint();

        // Create mint receipt with a wrong token
        let mint_receipt = token_messenger_minter::create_mint_receipt_for_testing(
            receipt, 
            @0xDEAD, 
            @0xDEADBEEF, 
            1000, 
            100);
        mint(mint_receipt);
    }

    #[test]
    #[expected_failure(abort_code = 0x50002, location = handler_registry)]
    fun test_mint_with_invalid_handler() {
        let owner = init_test_handler_and_tmm();

        // Update the handler from TMM to an invalid handler
        token_messenger_minter::test_register_handler(&owner, stablecoin_address(), @0xDEAD);

        let receipt = token_messenger_minter::create_test_receipt_for_mint();
        let mint_receipt = token_messenger_minter::prepare_mint(receipt);
        mint(mint_receipt);
    }

    #[test]
    #[expected_failure(abort_code = 0x60001, location = handler_registry)]
    fun test_mint_with_unregistered_handler() {
        let owner = init_test_handler_and_tmm();

        // deregister the handler from TMM
        token_messenger_minter::test_deregister_handler(&owner, stablecoin_address());

        let receipt = token_messenger_minter::create_test_receipt_for_mint();
        let mint_receipt = token_messenger_minter::prepare_mint(receipt);
        mint(mint_receipt);
    }

    // -----------------------------
    // ------- Burn Tests ----------
    // -----------------------------

    #[test]
    fun test_burn_success() {
        let owner = init_test_handler_and_tmm();

        // Mint tokens to owner for burning
        mint_stablecoin_for_testing(signer::address_of(&owner), 1_000_000);

        let amount = 1000u64;
        let token_obj: object::Object<Metadata> = object::address_to_object(stablecoin_address());
        
        // Withdraw for burning
        let burn_asset = primary_fungible_store::withdraw(&owner, token_obj, amount);

        // Create burn receipt using deposit_for_burn
        let mint_recipient = @0xDEADBEEF;
        let (burn_receipt, returned_asset) = token_messenger_minter::deposit_for_burn(
            &owner,
            burn_asset,
            4, // destination_domain (REMOTE_DOMAIN)
            mint_recipient,
            @0x0, // destination_caller
            100, // max_fee
            0, // min_finality_threshold
            vector::empty() // hook_data
        );

        // Execute burn
        burn(burn_receipt, returned_asset);
    }

    #[test]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_burn_with_wrong_token() {
        let owner = init_test_handler_and_tmm();        
        mint_stablecoin_for_testing(signer::address_of(&owner), 1_000_000);

        // Create burn receipt with a wrong burn token
        let mint_recipient = @0xDEADBEEF;
        let burn_receipt = 
        token_messenger_minter::create_burn_receipt_for_testing(
            @0xDEAD,
            @0xDEAD, // a wrong token
            100,
            4,
            mint_recipient,
            @0x0, // destination_caller
            @0x0,
            100,
            0,
            vector::empty()
        );

        let token_obj: object::Object<Metadata> = object::address_to_object(stablecoin_address());
        // Withdraw for burning
        let burn_asset = primary_fungible_store::withdraw(&owner, token_obj, 100);

        burn(burn_receipt, burn_asset);
    }

    #[test]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_burn_with_wrong_token_metadata() {
        init_test_handler_and_tmm();

        // Create accounts
        let asset_creator = create_signer_for_test(@0x9999);

        // Create a test fungible asset
        let fa_constructor_ref = object::create_named_object(&asset_creator, b"TestToken");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &fa_constructor_ref,
            option::none(),
            utf8(b"Test Token"),
            utf8(b"TEST"),
            8,
            utf8(b""),
            utf8(b""),
        );
        
        // Create a asset with amount 100
        let mint_ref = fungible_asset::generate_mint_ref(&fa_constructor_ref);
        let asset = mint_ref.mint(100);

        // Create burn receipt with a wrong burn token
        let mint_recipient = @0xDEADBEEF;
        let burn_receipt = token_messenger_minter::create_burn_receipt_for_testing(
            @0xDEAD,
            stablecoin_address(),
            100,
            4,
            mint_recipient,
            @0x0, // destination_caller
            @0x0,
            100,
            0,
            vector::empty()
        );

        burn(burn_receipt, asset);
    }

    #[test]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_burn_with_wrong_amount() {
        let owner = init_test_handler_and_tmm();        
        mint_stablecoin_for_testing(signer::address_of(&owner), 1_000_000);

        // Create burn receipt
        let mint_recipient = @0xDEADBEEF;
        let burn_receipt = token_messenger_minter::create_burn_receipt_for_testing(
            @0xDEAD,
            stablecoin_address(),
            100,
            4,
            mint_recipient,
            @0x0, // destination_caller
            @0x0,
            100,
            0,
            vector::empty()
        );

        let token_obj: object::Object<Metadata> = object::address_to_object(stablecoin_address());
        // Create an asset with amount 200 (Receipt amount is 100)
        let burn_asset = primary_fungible_store::withdraw(&owner, token_obj, 200);

        burn(burn_receipt, burn_asset);
    }

    #[test]
    #[expected_failure(abort_code = 0x60001, location = handler_registry)]
    fun test_burn_with_unregistered_handler() {
        let owner = init_test_handler_and_tmm();

        // deregister the handler from TMM
        token_messenger_minter::test_deregister_handler(&owner, stablecoin_address());

        // Mint tokens to owner for burning
        mint_stablecoin_for_testing(signer::address_of(&owner), 1_000_000);

        let amount = 1000u64;
        let token_obj: object::Object<Metadata> = object::address_to_object(stablecoin_address());

        // Withdraw for burning
        let burn_asset = primary_fungible_store::withdraw(&owner, token_obj, amount);

        // Create burn receipt using deposit_for_burn
        let mint_recipient = @0xDEADBEEF;
        let (burn_receipt, returned_asset) = token_messenger_minter::deposit_for_burn(
            &owner,
            burn_asset,
            4, // destination_domain (REMOTE_DOMAIN)
            mint_recipient,
            @0x0, // destination_caller
            100, // max_fee
            0, // min_finality_threshold
            vector::empty() // hook_data
        );

        // Execute burn
        burn(burn_receipt, returned_asset);
    }

    #[test]
    #[expected_failure(abort_code = 0x50002, location = handler_registry)]
    fun test_burn_with_invalid_handler() {
        let owner = init_test_handler_and_tmm();

        // Update the handler from TMM to an invalid handler
        token_messenger_minter::test_register_handler(&owner, stablecoin_address(), @0xDEAD);

        // Mint tokens to owner for burning
        mint_stablecoin_for_testing(signer::address_of(&owner), 1_000_000);

        let amount = 1000u64;
        let token_obj: object::Object<Metadata> = object::address_to_object(stablecoin_address());

        // Withdraw for burning
        let burn_asset = primary_fungible_store::withdraw(&owner, token_obj, amount);

        // Create burn receipt using deposit_for_burn
        let mint_recipient = @0xDEADBEEF;
        let (burn_receipt, returned_asset) = token_messenger_minter::deposit_for_burn(
            &owner,
            burn_asset,
            4, // destination_domain (REMOTE_DOMAIN)
            mint_recipient,
            @0x0, // destination_caller
            100, // max_fee
            0, // min_finality_threshold
            vector::empty() // hook_data
        );

        // Execute burn
        burn(burn_receipt, returned_asset);
    }

    // -----------------------------
    // ---- View Function Tests ----
    // -----------------------------

    #[test]
    fun test_supported_token() {
        init_test_stablecoin();
        assert_eq(supported_token(), stablecoin_address());
    }

    #[test]
    /// Test that handler_address returns a non-zero address
    fun test_handler_address() {
        let addr = handler_address();
        // handler_address is computed from the package address and seed
        // Just verify it's a valid computation
        assert!(addr != @0x0);
    }
}
