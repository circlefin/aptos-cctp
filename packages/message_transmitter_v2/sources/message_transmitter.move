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

module message_transmitter_v2::message_transmitter {
    // Built-in Modules
    use std::error;
    use std::signer;
    use aptos_framework::event;
    use aptos_framework::object;
    use aptos_framework::resource_account;
    use aptos_extensions::upgradable;
    use aptos_extensions::manageable;
    use aptos_extensions::pausable;
    use aptos_extensions::ownable;
    use cctp_extensions::rescuable;

    // Package Modules
    use message_transmitter_v2::state;
    use message_transmitter_v2::attester;
    use message_transmitter_v2::message;

    // Constants
    const SEED_NAME: vector<u8> = b"MessageTransmitter";

    // Errors
    const EMESSAGE_BODY_EXCEEDS_MAX_SIZE: u64 = 1;
    const EINVALID_RECIPIENT_ADDRESS: u64 = 2;
    const EALREADY_INITIALIZED: u64 = 3;
    const EINCORRECT_DESTINATION_DOMAIN: u64 = 4;
    const EINCORRECT_CALLER_FOR_THE_MESSAGE: u64 = 5;
    const EINVALID_MESSAGE_VERSION: u64 = 6;
    const ENONCE_ALREADY_USED: u64 = 7;
    const EUNAUTHORIZED_RECEIVING_ADDRESS: u64 = 8;
    const EINVALID_DOMAIN: u64 = 9;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// Store the extend ref to generate signer
    struct ObjectController has key {
        extend_ref: object::ExtendRef,
    }

    struct Receipt {
        caller: address,
        recipient: address,
        source_domain: u32,
        sender: address,
        nonce: u256,
        finality_threshold_executed: u32,
        message_body: vector<u8>
    }

    // -----------------------------
    // ---------- Events -----------
    // -----------------------------

    #[event]
    struct MessageSent has drop, store {
        message: vector<u8>
    }

    #[event]
    struct MessageReceived has drop, store {
        caller: address,
        source_domain: u32,
        nonce: u256,
        sender: address,
        finality_threshold_executed: u32,
        message_body: vector<u8>
    }

    #[event]
    struct MaxMessageBodySizeUpdated has drop, store {
        max_message_body_size: u64,
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    public fun local_domain(): u32 {
        state::get_local_domain()
    }

    #[view]
    public fun version(): u32 {
        state::get_version()
    }

    #[view]
    public fun is_nonce_used(nonce: u256): bool {
        state::is_nonce_used(nonce)
    }

    #[view]
    public fun max_message_body_size(): u64 {
        state::get_max_message_body_size()
    }

    #[view]
    public fun object_address(): address {
        state::get_object_address()
    }

    // -----------------------------
    // ----- Public Functions ------
    // -----------------------------

    fun init_module(resource_acct_signer: &signer) {
        let constructor_ref = object::create_named_object(resource_acct_signer, SEED_NAME);
        let message_transmitter_signer = &constructor_ref.generate_signer();
        let extend_ref = constructor_ref.generate_extend_ref();
        move_to(message_transmitter_signer, ObjectController { extend_ref });

        ownable::new(message_transmitter_signer, @deployer);
        pausable::new(message_transmitter_signer, @deployer);
        rescuable::new(&constructor_ref, @deployer);

        let signer_cap = resource_account::retrieve_resource_account_cap(resource_acct_signer, @deployer);
        manageable::new(resource_acct_signer, @deployer);
        upgradable::new(resource_acct_signer, signer_cap);
    }

    /// Create and initialize Message Transmitter object
    /// Aborts if:
    /// - caller is not the deployer
    /// - it has already been initialized
    entry fun initialize_message_transmitter(
        caller: &signer,
        local_domain: u32,
        attester: address,
        max_message_body_size: u64,
        version: u32
    ) {
        manageable::assert_is_admin(caller, @message_transmitter_v2);
        assert!(!state::is_initialized(), error::already_exists(EALREADY_INITIALIZED));
        state::init_state(caller, &get_signer(), local_domain, version, max_message_body_size);
        attester::init_attester(caller, attester);
    }

    /// Send the message to the destination domain and recipient, serializes the message and emits `MessageSent` event.
    /// Aborts if:
    /// - the contract is paused
    /// - domain is invalid
    /// - message body size exceeds the max size allowed
    /// - recipient is zero address
    public fun send_message(
        caller: &signer,
        destination_domain: u32,
        recipient: address,
        destination_caller: address,
        min_finality_threshold: u32,
        message_body: &vector<u8>
    ) {
        pausable::assert_not_paused(state::get_object_address());
        let sender_address = signer::address_of(caller);
        serialize_message_and_emit_event(
            destination_domain,
            recipient,
            sender_address,
            destination_caller,
            min_finality_threshold,
            message_body
        );
    }

    /// Receives a message. Messages with a given nonce can only be received once.
    /// Message format is defined in `message_transmitter_v2::message` module.
    /// A valid attestation is the concatenated 65-byte signature(s) of exactly `signature_threshold` signatures, in
    /// increasing order of attester address.
    ///
    /// Returns a `Receipt` hot potato that the receiving contract must consume via `complete_receive_message()`.
    /// The receiving contract processes its own logic, then calls `complete_receive_message()` with the receipt recipient which emits the
    /// `MessageReceived` event and destroys the `Receipt`.
    ///
    /// Example usage from a handler:
    /// ```
    ///     let receipt = message_transmitter::receive_message(caller, &message, &attestation);
    ///     // Handler processes receipt (e.g. prepare_mint / complete_mint)
    ///     // complete_receive_message must be called by the receipt recipient
    ///     message_transmitter::complete_receive_message(&recipient_signer, receipt);
    /// ```
    ///
    /// Aborts if:
    /// - the contract is paused
    /// - message format is invalid
    /// - attestation is invalid (wrong length, invalid signatures, wrong order)
    /// - destination domain doesn't match the local domain
    /// - destination caller is non-zero and doesn't match the caller
    /// - message version doesn't match the expected version
    /// - the nonce is already used
    public fun receive_message(caller: &signer, message_bytes: &vector<u8>, attestation: &vector<u8>): Receipt {
        pausable::assert_not_paused(state::get_object_address());
        message::validate_message(message_bytes);
        attester::verify_attestation_signature(message_bytes, attestation);

        // Validate destination domain
        let destination_domain = message::get_destination_domain_id(message_bytes);
        assert!(destination_domain == local_domain(), error::invalid_argument(EINCORRECT_DESTINATION_DOMAIN));

        // Validate destination caller
        let destination_caller = message::get_destination_caller(message_bytes);
        assert!(
            destination_caller == @0x0 || destination_caller == signer::address_of(caller),
            error::permission_denied(EINCORRECT_CALLER_FOR_THE_MESSAGE)
        );

        // Validate message version
        assert!(
            message::get_message_version(message_bytes) == version(),
            error::invalid_argument(EINVALID_MESSAGE_VERSION)
        );

        // Validate nonce is available and mark it used
        let nonce = message::get_nonce(message_bytes);
        assert!(!is_nonce_used(nonce), error::already_exists(ENONCE_ALREADY_USED));
        state::set_nonce_used(nonce);

        // Return unstamped receipt
        Receipt {
            caller: signer::address_of(caller),
            recipient: message::get_recipient_address(message_bytes),
            source_domain: message::get_src_domain_id(message_bytes),
            nonce,
            sender: message::get_sender_address(message_bytes),
            finality_threshold_executed: message::get_finality_threshold_executed(message_bytes),
            message_body: message::get_message_body(message_bytes)
        }
    }

    /// This function takes in a receipt, verifies it, emits `MessageReceived` event and destroys the receipt.
    /// Aborts if:
    /// - caller is not the receipt recipient
    public fun complete_receive_message(caller: &signer, receipt: Receipt) {
        assert!(
            receipt.recipient == signer::address_of(caller),
            error::permission_denied(EUNAUTHORIZED_RECEIVING_ADDRESS)
        );
        event::emit(MessageReceived {
            caller: receipt.caller,
            source_domain: receipt.source_domain,
            nonce: receipt.nonce,
            sender: receipt.sender,
            finality_threshold_executed: receipt.finality_threshold_executed,
            message_body: receipt.message_body
        });
        destroy_receipt(receipt);
    }

    /// Sets the max message body size (in bytes). Emits `MaxMessageBodySizeUpdated` event.
    /// Aborts if:
    /// - the caller is not the owner
    entry fun set_max_message_body_size(caller: &signer, new_max_message_body_size: u64) {
        ownable::assert_is_owner(caller, state::get_object_address());
        state::set_max_message_body_size(new_max_message_body_size);
        event::emit(MaxMessageBodySizeUpdated { max_message_body_size: new_max_message_body_size })
    }

    /// Public helper functions to retrieve struct fields since structs are only accessible within the same module
    public fun get_receipt_details(receipt: &Receipt): (address, address, u32, address, u32, vector<u8>) {
        (receipt.sender, receipt.recipient, receipt.source_domain, receipt.caller, receipt.finality_threshold_executed, receipt.message_body)
    }


    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    /// Generate signer from the `ExtendRef`
    fun get_signer(): signer {
        let object_address = state::get_object_address();
        let object_controller = borrow_global<ObjectController>(object_address);
        object_controller.extend_ref.generate_signer_for_extending()
    }

    fun serialize_message_and_emit_event(
        destination_domain: u32,
        recipient: address,
        sender_address: address,
        destination_caller: address,
        min_finality_threshold: u32,
        message_body: &vector<u8>
    ) {
        assert!(
            destination_domain != local_domain(),
            error::invalid_argument(EINVALID_DOMAIN)
        );
        assert!(
            message_body.length() <= state::get_max_message_body_size(),
            error::invalid_argument(EMESSAGE_BODY_EXCEEDS_MAX_SIZE)
        );
        assert!(recipient != @0x0, error::invalid_argument(EINVALID_RECIPIENT_ADDRESS));
        let message = message::serialize(
            version(),
            local_domain(),
            destination_domain,
            sender_address,
            recipient,
            destination_caller,
            min_finality_threshold,
            message_body
        );
        event::emit(MessageSent { message });
    }

    fun destroy_receipt(receipt: Receipt) {
        let Receipt {
            caller: _,
            recipient: _,
            source_domain: _,
            nonce: _,
            sender: _,
            finality_threshold_executed: _,
            message_body: _
        } = receipt;
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_framework::account::{Self, create_signer_for_test};
    #[test_only]
    use aptos_extensions::test_utils::{assert_eq};
    #[test_only]
    use aptos_extensions::ownable::OwnerRole;
    #[test_only]
    use aptos_extensions::pausable::PauseState;
    #[test_only]
    use cctp_extensions::rescuable::RescuableState;
    #[test_only]
    use message_transmitter_v2::serialize;

    // Test Helper Functions

    #[test_only]
    const RECEIVING_CONTRACT: address = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e;
    #[test_only]
    const TEST_SEED: vector<u8>  = b"test_seed_mt";

    #[test_only]
    fun init_test_message_transmitter_module(deployer: address) {
        account::create_account_for_test(deployer);
        resource_account::create_resource_account(
            &create_signer_for_test(deployer),
            TEST_SEED,
            x"",
        );
        let resource_account_address = account::create_resource_address(&deployer, TEST_SEED);
        assert_eq(@message_transmitter_v2, resource_account_address);
        let resource_account_signer = create_signer_for_test(resource_account_address);
        init_module(&resource_account_signer);
    }

    #[test_only]
    public fun initialize_test_message_transmitter(deployer: &signer) {
        init_test_message_transmitter_module(signer::address_of(deployer));
        initialize_message_transmitter(deployer, 9, @0x000000000000000000000000bcd4042de499d14e55001ccbb24a551f3b954096, 256, 1);
    }

    #[test_only]
    /// Creates a test message with v2 format
    fun get_test_message_v2(
        version: u32,
        source_domain: u32,
        destination_domain: u32,
        nonce: u256,
        sender: address,
        recipient: address,
        destination_caller: address,
        min_finality_threshold: u32,
        finality_threshold_executed: u32,
        message_body: &vector<u8>
    ): vector<u8> {
        use std::vector;
        let result = vector::empty<u8>();
        result.append(serialize::serialize_u32(version));
        result.append(serialize::serialize_u32(source_domain));
        result.append(serialize::serialize_u32(destination_domain));
        result.append(serialize::serialize_u256(nonce));
        result.append(serialize::serialize_address(sender));
        result.append(serialize::serialize_address(recipient));
        result.append(serialize::serialize_address(destination_caller));
        result.append(serialize::serialize_u32(min_finality_threshold));
        result.append(serialize::serialize_u32(finality_threshold_executed));
        result.append(*message_body);
        result
    }

    #[test_only]
    /// Test-only helper to create a Receipt for testing without going through attestation verification.
    /// This allows other packages to test their receive_message handling logic.
    public fun create_receipt_for_testing(
        caller: address,
        recipient: address,
        source_domain: u32,
        sender: address,
        nonce: u256,
        finality_threshold_executed: u32,
        message_body: vector<u8>
    ): Receipt {
        Receipt {
            caller,
            recipient,
            source_domain,
            sender,
            nonce,
            finality_threshold_executed,
            message_body,
        }
    }

    #[test_only]
    fun get_valid_send_message_and_attestation(): (vector<u8>, vector<u8>) {
        // Creates a test message with the following parameters:
        // - version: 1
        // - source_domain: 9 (local)
        // - destination_domain: 1 (remote - WRONG for receive tests)
        // - nonce: 1234
        // - sender: @deployer (0xc06c5aa31d28c27be8345770a83b48314b829039ec5a33b79265216c13c66071)
        // - recipient: 0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb
        // - destination_caller: 0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb
        // - min_finality_threshold: 1000
        // - finality_threshold_executed: 1000
        // - message_body: "Hello"
        let original_message = get_test_message_v2(
            1,
            9,
            1,
            1234,
            @deployer,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            1000,
            1000,
            &b"Hello");
        let original_attestation = x"f46eac44b9c194eda3bef338df3975dacff433de86e013e83fbbf669297f304f24eaec9593a8769f90797c59122d1ff992155d103cc5ba5288dc4e273c0107c61b";
        (original_message, original_attestation)
    }

    #[test_only]
    fun get_valid_receive_message_and_attestation(): (vector<u8>, vector<u8>){
        // Creates a test message with the following parameters:
        // - version: 1
        // - source_domain: 0
        // - destination_domain: 9
        // - nonce: 1234
        // - sender: 0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb
        // - recipient: RECEIVING_CONTRACT (0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e)
        // - destination_caller: @deployer (0xc06c5aa31d28c27be8345770a83b48314b829039ec5a33b79265216c13c66071)
        // - min_finality_threshold: 1000
        // - finality_threshold_executed: 1000
        // - message_body: "Hello"
        let message = get_test_message_v2(
            1,
            0,
            9,
            1234,
            @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb,
            RECEIVING_CONTRACT,
            @deployer,
            1000,
            1000,
            &b"Hello");
        let attestation = x"ef8e807a5cf82e33a07f6d68e33e47c3ca6bb8ad8fc1e4cce03f3cd45fc0549f7220fddc30f6d1c6f12f9d4ec7295c79fc0f3c17db6dabcfe285953b44f35b191c";
        (message, attestation)
    }

    #[test_only]
    public fun get_message_from_event(message_sent_event: &MessageSent): vector<u8> {
        message_sent_event.message
    }

    // Message Transmitter Initialization Tests

    #[test(owner = @deployer)]
    fun test_init_message_transmitter(owner: &signer) {
        initialize_test_message_transmitter(owner);
        assert_eq(state::is_initialized(), true);
        assert_eq(exists<ObjectController>(state::get_object_address()), true);
        assert_eq(attester::is_enabled_attester(attester::get_enabled_attester(0)), true);
        assert_eq(manageable::admin(@message_transmitter_v2), @deployer);
        assert_eq(ownable::owner(object::address_to_object<OwnerRole>(state::get_object_address())), @deployer);
        assert_eq(pausable::pauser(object::address_to_object<PauseState>(state::get_object_address())), @deployer);
        assert_eq(pausable::is_paused(object::address_to_object<PauseState>(state::get_object_address())), false);
        assert_eq(rescuable::rescuer(object::address_to_object<RescuableState>(state::get_object_address())), @deployer);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x80003, location = Self)]
    fun test_init_message_transmitter_already_initialized(owner: &signer) {
        initialize_test_message_transmitter(owner);
        initialize_message_transmitter(owner, 9, @0xfac, 256, 0);
    }

    #[test(not_owner = @0xfaa)]
    #[expected_failure(abort_code = manageable::ENOT_ADMIN, location = manageable)]
    fun test_init_message_transmitter_not_owner(not_owner: &signer) {
        init_test_message_transmitter_module(@deployer);
        initialize_message_transmitter(not_owner, 9, @0xfac, 256, 0);
    }

    // Send Message Tests

    #[test(owner = @deployer)]
    fun test_send_message_success(owner: &signer) {
        initialize_test_message_transmitter(owner);

        let recipient = @0xfac;
        let message_body = b"message";
        let destination_domain = 1;
        let destination_caller = @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb;
        let min_finality_threshold = 1000;
        send_message(owner, destination_domain, recipient, destination_caller, min_finality_threshold, &message_body);
        let expected_message = message::serialize(
            state::get_version(),
            state::get_local_domain(),
            destination_domain,
            @deployer,
            recipient,
            destination_caller,
            min_finality_threshold,
            &message_body
        );

        assert_eq(event::was_event_emitted(&MessageSent { message: expected_message }), true);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_send_message_contract_paused(owner: &signer) {
        initialize_test_message_transmitter(owner);
        state::set_paused(owner);
        send_message(owner, 1, @0xfac, @0x0, 0, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_send_message_excess_message_body_size(owner: &signer) {
        initialize_test_message_transmitter(owner);
        state::set_max_message_body_size(2);
        send_message(owner, 1, @0xfac, @0x0, 1000, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10002, location = Self)]
    fun test_send_message_zero_recipient_address(owner: &signer) {
        initialize_test_message_transmitter(owner);
        send_message(owner, 1, @0x0, @0x0, 1000, &b"message");
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10009, location = Self)]
    fun test_send_message_invalid_domain(owner: &signer) {
        initialize_test_message_transmitter(owner);
        send_message(owner, 9, @0xfac, @0x0, 1000, &b"message");
    }

    // Receive Message Tests

    #[test(
        owner = @deployer,
        receiving_contract = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e
    )]
    fun test_receive_message_success(owner: &signer, receiving_contract: &signer) {
        initialize_test_message_transmitter(owner);

        let source_domain = 0;
        let sender = @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb;
        let message_body = b"Hello";
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let nonce = message::get_nonce(&message);
        let receipt = receive_message(owner, &message, &attestation);

        assert_eq(receipt.nonce, nonce);
        assert_eq(receipt.recipient, RECEIVING_CONTRACT);
        assert_eq(receipt.sender, sender);
        assert_eq(receipt.source_domain, source_domain);
        assert_eq(receipt.message_body, message_body);

        complete_receive_message(receiving_contract, receipt);

        assert_eq(event::was_event_emitted(&MessageReceived {
            caller: signer::address_of(owner),
            source_domain,
            nonce,
            sender,
            finality_threshold_executed: 1000,
            message_body
        }), true);
        assert_eq(state::is_nonce_used(nonce), true);
    }

    #[test(
        owner = @deployer,
        receiving_contract = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e
    )]
    fun test_receive_message_empty_destination_caller(owner: &signer, receiving_contract: &signer) {
        initialize_test_message_transmitter(owner);

        let source_domain = 0;
        let sender = @0x1CD223dBC9ff35fF6B29dAB2339ACC842BF58cCb;
        let message_body = b"Hello";
        let recipient = RECEIVING_CONTRACT;
        let message = message::serialize(
            state::get_version(),
            source_domain,
            local_domain(),
            sender,
            recipient,
            @0x0,
            1000,
            &b"Hello"
        );
        let attestation = x"6226fbde152d922e928495362ec161d40eab4bd2b21f536b825c15a4d5d4e5d06046763b6d40c61dff4d079a14817a6e2b92bbcdf7f43a0faec7760fa8282fe71b";
        let nonce = message::get_nonce(&message);
        let receipt = receive_message(owner, &message, &attestation);

        assert_eq(receipt.nonce, nonce);
        assert_eq(receipt.recipient, recipient);
        assert_eq(receipt.sender, sender);
        assert_eq(receipt.source_domain, source_domain);
        assert_eq(receipt.message_body, message_body);

        complete_receive_message(receiving_contract, receipt);

        assert_eq(event::was_event_emitted(&MessageReceived {
            caller: signer::address_of(owner),
            source_domain,
            nonce,
            sender,
            finality_threshold_executed: 0,
            message_body
        }), true);
        assert_eq(state::is_nonce_used(nonce), true);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = pausable::EPAUSED, location = pausable)]
    fun test_receive_message_contract_paused(owner: &signer) {
        initialize_test_message_transmitter(owner);
        state::set_paused(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10001, location = message)]
    fun test_receive_message_invalid_message(owner: &signer) {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let invalid_message = message.slice(0, 10);
        let receipt = receive_message(owner, &invalid_message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x1000c, location = attester)]
    fun test_receive_message_invalid_attestation(owner: &signer) {
        initialize_test_message_transmitter(owner);
        let (message, _) = get_valid_receive_message_and_attestation();
        let (_, attestation) = get_valid_send_message_and_attestation();
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer, unauthorized_caller = @0xfaa)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_receive_message_not_authorized(owner: &signer, unauthorized_caller: &signer) {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let receipt = receive_message(unauthorized_caller, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10004, location = Self)]
    fun test_receive_message_incorrect_domain_id(owner: &signer) {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_send_message_and_attestation();
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_receive_message_invalid_message_version(owner: &signer) {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        state::set_version(2);
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x80007, location = Self)]
    fun test_receive_message_nonce_already_used(owner: &signer) {
        initialize_test_message_transmitter(owner);
        let (message, attestation) = get_valid_receive_message_and_attestation();
        let nonce = message::get_nonce(&message);
        state::set_nonce_used(nonce);
        let receipt = receive_message(owner, &message, &attestation);
        destroy_receipt(receipt)
    }

    // Complete Receive Message Tests

    #[test(
        owner = @deployer,
        receiving_contract = @0x7b62ddceded1acb449413404df81dd8d240f340605f626db1e15183cf04fa43e
    )]
    fun test_complete_receive_message_success(owner: &signer, receiving_contract: &signer) {
        initialize_test_message_transmitter(owner);
        let receipt = Receipt {
            caller: signer::address_of(owner),
            recipient: RECEIVING_CONTRACT,
            source_domain: 6,
            nonce: 523344,
            sender: @0xfaa,
            finality_threshold_executed: 1000,
            message_body: b"Message",
        };
        complete_receive_message(receiving_contract, receipt);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50008, location = Self)]
    fun test_complete_receive_message_unauthorized_caller(owner: &signer) {
        initialize_test_message_transmitter(owner);
        let stamped_receipt = Receipt {
            caller: signer::address_of(owner),
            recipient: RECEIVING_CONTRACT,
            source_domain: 6,
            nonce: 523344,
            sender: @0xfaa,
            finality_threshold_executed: 1000,
            message_body: b"Message",
        };
        complete_receive_message(owner, stamped_receipt);
    }

    // Set Max Message Body Size Tests

    #[test(owner = @deployer)]
    fun test_set_max_message_body_size_success(owner: &signer) {
        initialize_test_message_transmitter(owner);
        set_max_message_body_size(owner, 512);
        assert_eq(state::get_max_message_body_size(), 512);
        assert_eq(event::was_event_emitted(&MaxMessageBodySizeUpdated {
            max_message_body_size: 512
        }), true)
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_set_max_message_body_size_not_owner(owner: &signer) {
        initialize_test_message_transmitter(owner);
        state::set_owner(@0xfaa);
        set_max_message_body_size(owner, 512);
    }

    // Get Receipt Details test

    #[test]
    fun test_get_receipt_details() {
        let receipt = Receipt {
            caller: @0xfac,
            recipient: @0xfaa,
            source_domain: 1,
            sender: @0xfab,
            nonce: 5723,
            finality_threshold_executed: 1000,
            message_body: b"message_body"
        };

        let (sender, recipient, source_domain, caller, finality_threshold_executed, message_body) = get_receipt_details(&receipt);
        assert_eq(recipient, @0xfaa);
        assert_eq(source_domain, 1);
        assert_eq(sender, @0xfab);
        assert_eq(caller, @0xfac);
        assert_eq(finality_threshold_executed, 1000);
        assert_eq(message_body, b"message_body");
        destroy_receipt(receipt);
    }

    // View Function Tests

    #[test(owner = @deployer)]
    fun test_is_nonce_used(owner: &signer) {
        initialize_test_message_transmitter(owner);
        let key: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111;
        state::set_nonce_used(key);
        assert_eq(is_nonce_used(key), true);
    }

    #[test(owner = @deployer)]
    fun test_max_message_body_size(owner: &signer) {
        initialize_test_message_transmitter(owner);
        assert_eq(max_message_body_size(), state::get_max_message_body_size());
    }

    #[test(owner = @deployer)]
    fun test_object_address(owner: &signer) {
        initialize_test_message_transmitter(owner);
        assert_eq(object_address(), state::get_object_address());
    }

    #[test(owner = @deployer)]
    fun test_local_domain(owner: &signer) {
        initialize_test_message_transmitter(owner);
        assert_eq(local_domain(), state::get_local_domain());
    }

    #[test(owner = @deployer)]
    fun test_version(owner: &signer) {
        initialize_test_message_transmitter(owner);
        assert_eq(version(), state::get_version());
    }
}
