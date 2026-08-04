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

module token_messenger_minter_v2::denylistable {
    use std::error;
    use std::signer;
    use std::table_with_length::{Self, TableWithLength};
    use aptos_framework::event;
    use aptos_extensions::ownable;
    use token_messenger_minter_v2::state;

    // === Errors ===

    /// Caller is not the denylister
    const ENOT_DENYLISTER: u64 = 1;
    /// New denylister is the same as the old denylister
    const ENEW_DENYLISTER_SAME_AS_OLD: u64 = 2;
    /// Invalid denylister address
    const EINVALID_DENYLISTER_ADDRESS: u64 = 3;
    /// Address is denylisted
    const EDENYLISTED_ADDRESS: u64 = 4;

    // === Structs ===

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// The denylist state
    struct DenylistState has key {
        denylisted: TableWithLength<address, bool>,
        denylister: address,
    }

    // === Events ===

    #[event]
    /// Emitted when an address is added to the denylist
    struct Denylisted has drop, store {
        address: address,
    }

    #[event]
    /// Emitted when an address is removed from the denylist
    struct UnDenylisted has drop, store {
        address: address,
    }

    #[event]
    /// Emitted when the denylister address is changed
    struct DenylisterChanged has drop, store {
        old_denylister: address,
        new_denylister: address,
    }

    // === View-only functions ===

    #[view]
    /// Returns whether an address is denylisted
    public fun is_denylisted(addr: address): bool {
        borrow_global<DenylistState>(state::get_object_address()).denylisted.contains(addr)
    }

    #[view]
    /// Gets the denylister address
    public fun denylister(): address {
        borrow_global<DenylistState>(state::get_object_address()).denylister
    }

    public fun assert_not_denylisted(addr: address) {
        assert!(!is_denylisted(addr), error::invalid_argument(EDENYLISTED_ADDRESS));
    }

    // === Write functions ===

    /// Creates and inits a new denylist state
    package fun new(signer: &signer, denylister: address) {
        assert!(denylister != @0x0, error::invalid_argument(EINVALID_DENYLISTER_ADDRESS));
        move_to(signer, DenylistState { 
            denylisted: table_with_length::new(),
            denylister
        });
    }

    /// Adds an address to the denylist
    entry fun denylist(caller: &signer, address: address) {
        let denylist_state = borrow_global_mut<DenylistState>(state::get_object_address());
        assert!(denylist_state.denylister == signer::address_of(caller), error::permission_denied(ENOT_DENYLISTER));

        if (!denylist_state.denylisted.contains(address)) {
            denylist_state.denylisted.add(address, true);
            event::emit(Denylisted { address });
        };
    }

    /// Removes an address from the denylist
    entry fun undenylist(caller: &signer, address: address) {
        let denylist_state = borrow_global_mut<DenylistState>(state::get_object_address());
        assert!(denylist_state.denylister == signer::address_of(caller), error::permission_denied(ENOT_DENYLISTER));
        if (denylist_state.denylisted.contains(address)) {
            denylist_state.denylisted.remove(address);
            event::emit(UnDenylisted { address });
        };
    }

    /// Changes the denylister address
    entry fun update_denylister(caller: &signer, new_denylister: address) {
        assert!(new_denylister != @0x0, error::invalid_argument(EINVALID_DENYLISTER_ADDRESS));

        let obj_address = state::get_object_address();
        ownable::assert_is_owner(caller, obj_address);

        let denylist_state = borrow_global_mut<DenylistState>(obj_address);
        assert!(denylist_state.denylister != new_denylister, error::invalid_argument(ENEW_DENYLISTER_SAME_AS_OLD));

        let old_denylister = denylist_state.denylister;
        denylist_state.denylister = new_denylister;
        event::emit(DenylisterChanged { old_denylister, new_denylister });
    }

    // === Test-only ===
    #[test_only]
    use aptos_framework::object;
    #[test_only]
    use aptos_extensions::test_utils::{assert_eq};
    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    const RANDOM_ADDRESS: address = @0x4444;
    #[test_only]
    const OWNER_ADDRESS: address = @0x1111;
    #[test_only]
    const DENYLISTER_ADDRESS: address = @0x2222;
    #[test_only]
    const DENYLISTER_ADDRESS_2: address = @0x3333;
    #[test_only]
    const SEED_NAME: vector<u8> = b"TokenMessengerMinter";

    #[test_only]
    fun create_resource(): signer {
        let resource_account_address = account::create_resource_address(&@deployer, b"test_seed_tmm");
        let resource_account_signer = create_signer_for_test(resource_account_address);
        let constructor_ref = object::create_named_object(&resource_account_signer, SEED_NAME);
        let signer = constructor_ref.generate_signer();
        ownable::new(&signer, OWNER_ADDRESS);
        signer
    }

    #[test_only]
    public fun set_denylisted_for_testing(addr: address, denylisted: bool) {
        let denylist_state = borrow_global_mut<DenylistState>(state::get_object_address());
        if (denylisted) {
            denylist_state.denylisted.add(addr, true);
        } else if (denylist_state.denylisted.contains(addr)) {
            denylist_state.denylisted.remove(addr);
        }
    }

    #[test_only]
    fun setup() {
        let signer = &create_resource();
        new(signer, DENYLISTER_ADDRESS);
    }

    #[test]
    fun is_denylisted__should_return_true_if_address_is_denylisted() {
        setup();
        set_denylisted_for_testing(RANDOM_ADDRESS, true);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            true
        );
    }

    #[test]
    fun is_denylisted__should_return_false_by_default() {
        setup();
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            false
        );
    }

    #[test]
    fun is_denylisted__should_return_false_if_not_denylisted() {
        setup();
        set_denylisted_for_testing(RANDOM_ADDRESS, false);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            false
        );
    }

    #[test]
    fun denylister__should_return_denylister_address() {
        setup();
        assert_eq(
            denylister(),
            DENYLISTER_ADDRESS
        );
    }

    #[test]
    fun assert_not_denylisted__should_succeed_if_address_is_not_denylisted() {
        setup();
        assert_not_denylisted(RANDOM_ADDRESS);
    }

    #[test, expected_failure(abort_code = 0x10004, location = Self)]
    fun assert_not_denylisted__should_fail_if_address_is_denylisted() {
        setup();
        set_denylisted_for_testing(RANDOM_ADDRESS, true);
        assert_not_denylisted(RANDOM_ADDRESS);
    }

    #[test]
    fun new__should_set_denylist_state() {
        let signer = &create_resource();
        new(signer, DENYLISTER_ADDRESS);
        assert_eq(
            denylister(),
            DENYLISTER_ADDRESS
        );
    }

    #[test, expected_failure(abort_code = 0x10003, location = Self)]
    fun new__should_fail_if_denylister_address_is_invalid() {
        let signer = &create_resource();

        new(signer, @0x0);
    }

    #[test]
    fun denylist__should_add_address_to_denylist() {
        setup();

        let denylister_signer = &create_signer_for_test(DENYLISTER_ADDRESS);
        denylist(denylister_signer, RANDOM_ADDRESS);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            true
        );
        assert_eq(event::was_event_emitted(&Denylisted { address: RANDOM_ADDRESS }), true);
    }

    #[test]
    fun denylist__should_be_idempotent() {
        setup();
        set_denylisted_for_testing(RANDOM_ADDRESS, true);
        denylist(&create_signer_for_test(DENYLISTER_ADDRESS), RANDOM_ADDRESS);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            true
        );
    }

    #[test, expected_failure(abort_code = 0x50001, location = Self)]
    fun denylist__should_fail_if_caller_is_not_denylister() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);
        denylist(caller, RANDOM_ADDRESS);
    }

    #[test]
    fun undenylist__should_remove_address_from_denylist() {
        setup();
        let denylister_signer = &create_signer_for_test(DENYLISTER_ADDRESS);
        set_denylisted_for_testing(RANDOM_ADDRESS, true);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            true
        );

        undenylist(denylister_signer, RANDOM_ADDRESS);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            false
        );

        assert_eq(event::was_event_emitted(&UnDenylisted { address: RANDOM_ADDRESS }), true);
    }

    #[test]
    fun undenylist__should_succeed_on_undenylisted_address() {
        setup();
        undenylist(&create_signer_for_test(DENYLISTER_ADDRESS), RANDOM_ADDRESS);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            false
        );
    }

    #[test]
    fun undenylist__should_be_idempotent() {
        setup();
        set_denylisted_for_testing(RANDOM_ADDRESS, true);
        let denylister_signer = &create_signer_for_test(DENYLISTER_ADDRESS);
        undenylist(denylister_signer, RANDOM_ADDRESS);
        undenylist(denylister_signer, RANDOM_ADDRESS);
        assert_eq(
            is_denylisted(RANDOM_ADDRESS),
            false
        );
    }

    #[test, expected_failure(abort_code = 0x50001, location = Self)]
    fun undenylist__should_fail_if_caller_is_not_denylister() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);
        undenylist(caller, RANDOM_ADDRESS);
    }

    #[test]
    fun update_denylister__should_change_denylister_address() {
        setup();
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);

        update_denylister(owner_signer, DENYLISTER_ADDRESS_2);
        assert_eq(
            denylister(),
            DENYLISTER_ADDRESS_2
        );

        assert_eq(event::was_event_emitted(&DenylisterChanged { old_denylister: DENYLISTER_ADDRESS, new_denylister: DENYLISTER_ADDRESS_2 }), true);
    }

    #[test, expected_failure(abort_code = 0x10002, location = Self)]
    fun update_denylister__should_fail_if_new_denylister_is_the_same_as_the_old_denylister() {
        setup();
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);
        update_denylister(owner_signer, DENYLISTER_ADDRESS);
    }

    #[test, expected_failure(abort_code = ownable::ENOT_OWNER)]
    fun update_denylister__should_fail_if_caller_is_not_owner() {
        setup();
        let caller = &create_signer_for_test(RANDOM_ADDRESS);
        update_denylister(caller, DENYLISTER_ADDRESS_2);
    }

    #[test, expected_failure(abort_code = 0x10003, location = Self)]
    fun update_denylister__should_fail_if_new_denylister_address_is_invalid() {
        setup();
        let owner_signer = &create_signer_for_test(OWNER_ADDRESS);
        update_denylister(owner_signer, @0x0);
    }
}
