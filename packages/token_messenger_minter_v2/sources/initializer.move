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

/// Infrastructure module for TokenMessengerMinter.
/// Handles object lifecycle, signer management, and package initialization.
module token_messenger_minter_v2::initializer {
    // Built-in Modules
    use std::error;
    use aptos_framework::object;
    use aptos_framework::resource_account;
    use aptos_extensions::upgradable;
    use aptos_extensions::manageable;
    use aptos_extensions::pausable;
    use aptos_extensions::ownable;
    use cctp_extensions::rescuable;

    // Package Modules
    use token_messenger_minter_v2::state;
    use token_messenger_minter_v2::token_controller;
    use token_messenger_minter_v2::handler_registry;
    use token_messenger_minter_v2::denylistable;
    use token_messenger_minter_v2::fee_controller;

    // Friends
    // Constants
    const SEED_NAME: vector<u8> = b"TokenMessengerMinter";

    // Errors
    const EALREADY_INITIALIZED: u64 = 1;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct ObjectController has key {
        extend_ref: object::ExtendRef,
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
        let token_messenger_minter_signer = &constructor_ref.generate_signer();
        let extend_ref = constructor_ref.generate_extend_ref();
        move_to(token_messenger_minter_signer, ObjectController { extend_ref });

        ownable::new(token_messenger_minter_signer, @deployer);
        pausable::new(token_messenger_minter_signer, @deployer);
        denylistable::new(token_messenger_minter_signer, @deployer);
        fee_controller::new(token_messenger_minter_signer, @deployer, @deployer);

        // Initialize handler registry
        handler_registry::new(token_messenger_minter_signer);

        // Initialize rescuer
        rescuable::new(&constructor_ref, @deployer);

        let signer_cap = resource_account::retrieve_resource_account_cap(resource_acct_signer, @deployer);
        manageable::new(resource_acct_signer, @deployer);
        upgradable::new(resource_acct_signer, signer_cap);
    }

    /// Create and initialize Token Messenger Minter object
    /// Aborts if:
    /// - caller is not the deployer
    /// - it has already been initialized
    entry fun initialize_token_messenger_minter(
        caller: &signer,
        message_body_version: u32,
        token_controller: address,
        fee_recipient: address,
    ) {
        manageable::assert_is_admin(caller, @token_messenger_minter_v2);
        assert!(!state::is_initialized(), error::already_exists(EALREADY_INITIALIZED));
        state::init_state(&get_signer(), message_body_version);
        token_controller::set_token_controller(caller, token_controller);
        fee_controller::set_fee_recipient(caller, fee_recipient);
    }

    // -----------------------------
    // ----- Friend Functions ------
    // -----------------------------

    /// Generate signer from the `ExtendRef` to call `TokenMinter` and `MessageTransmitter`
    /// Only accessible within the package
    package fun get_signer(): signer {
        let object_address = state::get_object_address();
        let object_controller = borrow_global<ObjectController>(object_address);
        object_controller.extend_ref.generate_signer_for_extending()
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use std::vector;
    #[test_only]
    use aptos_extensions::ownable::OwnerRole;
    #[test_only]
    use aptos_extensions::pausable::PauseState;
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;
    #[test_only]
    use cctp_extensions::rescuable::RescuableState;

    #[test_only]
    const TEST_SEED: vector<u8> = b"test_seed_tmm";

    #[test_only]
    public fun init_test_initializer_module() {
        account::create_account_for_test(@deployer);
        resource_account::create_resource_account_and_publish_package(
            &create_signer_for_test(@deployer),
            TEST_SEED,
            x"04746573740100000000000000000000000000", // empty BCS serialized PackageMetadata
            vector::empty()
        );
        let resource_account_address = account::create_resource_address(&@deployer, TEST_SEED);
        assert_eq(@token_messenger_minter_v2, resource_account_address);
        let resource_account_signer = create_signer_for_test(resource_account_address);
        init_module(&resource_account_signer);
    }

    #[test_only]
    public fun initialize_test_token_messenger_minter(
        message_body_version: u32,
        token_controller: address,
        fee_recipient: address,
    ) {
        init_test_initializer_module();
        initialize_token_messenger_minter(&create_signer_for_test(@deployer), message_body_version, token_controller, fee_recipient);
    }

    #[test_only]
    public fun get_signer_for_testing(): signer {
        get_signer()
    }

    // Token Messenger Minter Initialization Tests

    #[test]
    fun test_init_token_messenger_minter() {
        initialize_test_token_messenger_minter(1, @0xfac, @0xfad);
        assert!(state::is_initialized());
        assert_eq(state::get_token_controller(), @0xfac);
        assert_eq(fee_controller::get_fee_recipient(), @0xfad);
        assert!(exists<ObjectController>(state::get_object_address()));
        assert_eq(manageable::admin(@token_messenger_minter_v2), @deployer);
        assert_eq(ownable::owner(object::address_to_object<OwnerRole>(state::get_object_address())), @deployer);
        assert_eq(pausable::pauser(object::address_to_object<PauseState>(state::get_object_address())), @deployer);
        assert!(!pausable::is_paused(object::address_to_object<PauseState>(state::get_object_address())));
        // Verify handler_registry is initialized (no handlers registered yet)
        assert!(!handler_registry::is_handler_registered(@0x1));
        assert_eq(denylistable::denylister(), @deployer);
        assert_eq(rescuable::rescuer(object::address_to_object<RescuableState>(state::get_object_address())), @deployer);
    }

    #[test(owner = @deployer)]
    #[expected_failure(abort_code = 0x80001, location = Self)]
    fun test_init_token_messenger_minter_already_initialized(owner: &signer) {
        initialize_test_token_messenger_minter(1, @0xfac, @0xfad);
        initialize_token_messenger_minter(owner, 2, @0xfab, @0xfad);
    }

    #[test(not_owner = @0xfaa)]
    #[expected_failure(abort_code = manageable::ENOT_ADMIN, location = manageable)]
    fun test_init_token_messenger_minter_not_owner(not_owner: &signer) {
        init_test_initializer_module();
        initialize_token_messenger_minter(not_owner, 1, @0xfac, @0xfad);
    }

    #[test]
    fun test_object_address() {
        init_test_initializer_module();
        assert_eq(object_address(), state::get_object_address());
    }
}

