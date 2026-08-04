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

/// Handler registry for the multi-token CCTP architecture.
/// Maps token addresses to their registered handler addresses.
/// Only registered handlers can mint tokens via the TokenMessengerMinter.
module token_messenger_minter_v2::handler_registry {
    // Built-in Modules
    use std::error;
    use std::signer;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_framework::event;
    use aptos_extensions::ownable;

    // Package Modules
    use token_messenger_minter_v2::state;

    // Errors
    const ENO_HANDLER_REGISTERED: u64 = 1;
    const ENOT_REGISTERED_HANDLER: u64 = 2;
    const EINVALID_HANDLER_ADDRESS: u64 = 3;
    const EINVALID_TOKEN_ADDRESS: u64 = 4;

    // -----------------------------
    // ----------- State -----------
    // -----------------------------

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct HandlerRegistry has key {
        /// Maps token_address => handler signer address
        handlers: BigOrderedMap<address, address>,
    }

    // -----------------------------
    // ---------- Events -----------
    // -----------------------------

    #[event]
    struct HandlerRegistered has drop, store {
        token_address: address,
        handler_address: address,
    }

    #[event]
    struct HandlerDeregistered has drop, store {
        token_address: address,
        handler_address: address,
    }

    // -----------------------------
    // ----- Package Functions ------
    // -----------------------------

    /// Initialize the handler registry (called by initializer)
    package fun new(tmm_signer: &signer) {
        move_to(tmm_signer, HandlerRegistry {
            handlers: big_ordered_map::new(),
        });
    }

    // -----------------------------
    // ----- Entry Functions -------
    // -----------------------------

    /// Register a handler for a token (owner only)
    /// Aborts if:
    /// - caller is not the owner
    /// - invalid token address
    /// - invalid handler address
    entry fun register_handler(
        owner: &signer,
        token_address: address,
        handler_signer_address: address,
    ) {
        ownable::assert_is_owner(owner, state::get_object_address());

        assert!(token_address != @0x0, error::invalid_argument(EINVALID_TOKEN_ADDRESS));
        assert!(handler_signer_address != @0x0, error::invalid_argument(EINVALID_HANDLER_ADDRESS));

        let registry = borrow_global_mut<HandlerRegistry>(state::get_object_address());
        registry.handlers.upsert(token_address, handler_signer_address);

        event::emit(HandlerRegistered { token_address, handler_address: handler_signer_address });
    }

    /// Deregister a handler for a token (owner only) - EMERGENCY USE
    /// Aborts if:
    /// - caller is not the owner
    /// - invalid token address
    /// - no handler is registered for the token
    entry fun deregister_handler(
        owner: &signer,
        token_address: address,
    ) {
        ownable::assert_is_owner(owner, state::get_object_address());

        assert!(token_address != @0x0, error::invalid_argument(EINVALID_TOKEN_ADDRESS));

        let registry = borrow_global_mut<HandlerRegistry>(state::get_object_address());
        assert!(
            registry.handlers.contains(&token_address),
            error::not_found(ENO_HANDLER_REGISTERED)
        );

        let handler_address = registry.handlers.remove(&token_address);

        event::emit(HandlerDeregistered { token_address, handler_address });
    }

    // -----------------------------
    // ----- Public Functions ------
    // -----------------------------

    /// Verify caller is registered handler for token
    /// Aborts if: no handler registered or caller is not the registered handler
    public fun assert_is_registered_handler(
        handler_signer: &signer,
        token_address: address
    ) {
        let registry = borrow_global<HandlerRegistry>(state::get_object_address());
        assert!(
            registry.handlers.contains(&token_address),
            error::not_found(ENO_HANDLER_REGISTERED)
        );
        let registered = registry.handlers.borrow(&token_address);
        assert!(
            signer::address_of(handler_signer) == *registered,
            error::permission_denied(ENOT_REGISTERED_HANDLER)
        );
    }

    // -----------------------------
    // --- Public View Functions ---
    // -----------------------------

    #[view]
    /// Check if a handler is registered for a token
    public fun is_handler_registered(token_address: address): bool {
        let registry = borrow_global<HandlerRegistry>(state::get_object_address());
        registry.handlers.contains(&token_address)
    }

    #[view]
    /// Get the handler address for a token
    /// Aborts if no handler is registered
    public fun get_handler(token_address: address): address {
        let registry = borrow_global<HandlerRegistry>(state::get_object_address());
        assert!(
            registry.handlers.contains(&token_address),
            error::not_found(ENO_HANDLER_REGISTERED)
        );
        *registry.handlers.borrow(&token_address)
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;

    #[test_only]
    /// Test-only helper to initialize state and handler_registry for unit tests.
    /// This avoids circular dependency with initializer module.
    fun init_test_handler_registry(owner: &signer) {
        // Initialize state and get the TMM object signer
        let tmm_signer = state::init_test_state_and_get_signer(owner);
        
        // Initialize handler registry on the same object
        new(&tmm_signer);
    }

    #[test_only]
    /// Test-only helper to register a handler (for use by other test modules).
    public fun test_register_handler_for_testing(owner: &signer, token_address: address, handler_address: address) {
        register_handler(owner, token_address, handler_address);
    }

    #[test_only]
    /// Test-only helper to deregister a handler (for use by other test modules).
    public fun test_deregister_handler_for_testing(owner: &signer, token_address: address) {
        deregister_handler(owner, token_address);
    }

    // Register Handler Tests

    #[test(owner = @deployer)]
    fun test_register_handler_success(owner: &signer) {
        init_test_handler_registry(owner);
        let token_address = @0xbeef;
        let handler_address = @0xcafe;

        register_handler(owner, token_address, handler_address);

        assert!(is_handler_registered(token_address), 0);
        assert_eq(get_handler(token_address), handler_address);
        assert!(event::was_event_emitted(&HandlerRegistered { token_address, handler_address }), 0);
    }

    #[test(owner = @deployer)]
    fun test_register_handler_update_existing(owner: &signer) {
        init_test_handler_registry(owner);
        let token_address = @0xbeef;
        let handler_address_1 = @0xcafe1;
        let handler_address_2 = @0xcafe2;

        register_handler(owner, token_address, handler_address_1);
        assert_eq(get_handler(token_address), handler_address_1);

        register_handler(owner, token_address, handler_address_2);
        assert_eq(get_handler(token_address), handler_address_2);
    }

    #[test(owner = @deployer, not_owner = @0xfaa)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_register_handler_not_owner(owner: &signer, not_owner: &signer) {
        init_test_handler_registry(owner);
        register_handler(not_owner, @0xbeef, @0xcafe);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10004, location = Self)]
    fun test_register_handler_invalid_token_address(owner: &signer) {
        init_test_handler_registry(owner);
        register_handler(owner, @0x0, @0xcafe);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun test_register_handler_invalid_handler_address(owner: &signer) {
        init_test_handler_registry(owner);
        register_handler(owner, @0xbeef, @0x0);
    }

    // Deregister Handler Tests

    #[test(owner = @deployer)]
    fun test_deregister_handler(owner: &signer) {
        init_test_handler_registry(owner);
        let token_address = @0xbeef;
        let handler_address = @0xcafe;

        register_handler(owner, token_address, handler_address);
        assert!(is_handler_registered(token_address), 0);

        deregister_handler(owner, token_address);
        assert!(!is_handler_registered(token_address), 0);
        assert!(event::was_event_emitted(&HandlerDeregistered { token_address, handler_address }), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_deregister_handler_not_registered(owner: &signer) {
        init_test_handler_registry(owner);
        deregister_handler(owner, @0xbeef);
    }

    #[test(owner = @deployer, not_owner = @0xfaa)]
    #[expected_failure(abort_code = ownable::ENOT_OWNER, location = ownable)]
    fun test_deregister_handler_not_owner(owner: &signer, not_owner: &signer) {
        init_test_handler_registry(owner);
        register_handler(owner, @0xbeef, @0xcafe);
        deregister_handler(not_owner, @0xbeef);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x10004, location = Self)]
    fun test_deregister_handler_invalid_token_address(owner: &signer) {
        init_test_handler_registry(owner);
        deregister_handler(owner, @0x0);
    }

    // Assert Is Registered Handler Tests

    #[test(owner = @deployer)]
    fun test_assert_is_registered_handler_success(owner: &signer) {
        init_test_handler_registry(owner);
        let token_address = @0xbeef;
        let handler_address = @0xcafe;

        register_handler(owner, token_address, handler_address);

        let handler_signer = create_signer_for_test(handler_address);
        assert_is_registered_handler(&handler_signer, token_address);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_assert_is_registered_handler_not_registered(owner: &signer) {
        init_test_handler_registry(owner);
        let handler_signer = create_signer_for_test(@0xcafe);
        assert_is_registered_handler(&handler_signer, @0xbeef);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x50002, location = Self)]
    fun test_assert_is_registered_handler_wrong_handler(owner: &signer) {
        init_test_handler_registry(owner);
        let token_address = @0xbeef;

        register_handler(owner, token_address, @0xcafe1);

        let wrong_handler_signer = create_signer_for_test(@0xcafe2);
        assert_is_registered_handler(&wrong_handler_signer, token_address);
    }

    // View Function Tests

    #[test(owner = @deployer)]
    fun test_is_handler_registered_false(owner: &signer) {
        init_test_handler_registry(owner);
        assert!(!is_handler_registered(@0xbeef), 0);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_get_handler_not_registered(owner: &signer) {
        init_test_handler_registry(owner);
        get_handler(@0xbeef);
    }
}

