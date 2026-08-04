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

module cctp_extensions::rescuable {
    use std::error;
    use std::signer;
    use aptos_framework::event;
    use aptos_framework::object::{Self, Object, ConstructorRef};
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::primary_fungible_store;
    use aptos_extensions::ownable::{Self, OwnerRole};

    // === Errors ===

    /// Non-existent OwnerRole object
    const ENON_EXISTENT_OWNER: u64 = 1;
    /// Caller is not the rescuer
    const ENOT_RESCUER: u64 = 2;
    /// New rescuer is the same as the old rescuer
    const ENEW_RESCUER_SAME_AS_OLD: u64 = 3;

    // === Structs ===

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct RescuableState has key {
        rescuer: address,
        extend_ref: object::ExtendRef,
    }

    // === Events ===

    #[event]
    struct RescuerChanged has drop, store {
        obj_address: address,
        new_rescuer: address,
    }

    #[event]
    struct RescuableStateDestroyed has drop, store {
        obj_address: address,
    }

    // === View-only functions ===

    #[view]
    public fun rescuer(obj: Object<RescuableState>): address {
        borrow_global<RescuableState>(obj.object_address()).rescuer
    }

    // === Write functions ===

    /// Creates and inits a new rescuer state
    /// Must be called after ownable::new() to ensure OwnerRole exists
    public fun new(constructor_ref: &ConstructorRef, rescuer: address) {
        let obj_signer = &constructor_ref.generate_signer();
        let obj_address = signer::address_of(obj_signer);
        assert!(object::object_exists<OwnerRole>(obj_address), error::not_found(ENON_EXISTENT_OWNER));
        move_to(obj_signer, RescuableState { rescuer, extend_ref: constructor_ref.generate_extend_ref() });
    }

    /// Changes the rescuer address
    entry fun update_rescuer(caller: &signer, obj: Object<RescuableState>, new_rescuer: address) {
        let obj_address = obj.object_address();
        ownable::assert_is_owner(caller, obj_address);

        let rescuer_state = borrow_global_mut<RescuableState>(obj_address);
        assert!(rescuer_state.rescuer != new_rescuer, error::invalid_argument(ENEW_RESCUER_SAME_AS_OLD));

        rescuer_state.rescuer = new_rescuer;
        event::emit(RescuerChanged { obj_address, new_rescuer });
    }

    /// Rescues fungible assets from the object's primary store to a recipient address
    /// Only callable by the rescuer
    entry fun rescue_fungible_asset(
        caller: &signer,
        obj: Object<RescuableState>,
        metadata: Object<Metadata>,
        to: address,
        amount: u64
    ) {
        let obj_address = obj.object_address();
        let rescuer_state = borrow_global<RescuableState>(obj_address);
        assert!(rescuer_state.rescuer == signer::address_of(caller), error::permission_denied(ENOT_RESCUER));

        // Generate signer for the object to transfer from its primary fungible store
        let obj_signer = rescuer_state.extend_ref.generate_signer_for_extending();
        primary_fungible_store::transfer(
            &obj_signer,
            metadata,
            to,
            amount
        );
    }

    /// Removes the RescuableState resource from the caller
    public fun destroy(caller: &signer) {
        let obj_address = signer::address_of(caller);
        let RescuableState { rescuer: _, extend_ref: _ } = move_from<RescuableState>(obj_address);
        event::emit(RescuableStateDestroyed { obj_address });
    }

    // === Test-only ===
    #[test_only]
    use aptos_extensions::ownable::new as new_ownerable;
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_framework::fungible_asset;
    #[test_only]
    use std::string::utf8;
    #[test_only]
    use std::option;

    #[test_only]
    const RANDOM_ADDRESS: address = @0x4444;

    #[test_only]
    const OWNER_ADDRESS: address = @0x1111;
    #[test_only]
    const RESCUE_ADDRESS: address = @0x2222;
    #[test_only]
    const RESCUE_ADDRESS_2: address = @0x3333;

    #[test_only]
    fun setup_rescuable(): (signer, Object<RescuableState>) {
        let constructor_ref = object::create_sticky_object(@0x10);
        let obj_address = constructor_ref.address_from_constructor_ref();
        let signer = constructor_ref.generate_signer();
        
        new_ownerable(&signer, OWNER_ADDRESS);
        new(&constructor_ref, RESCUE_ADDRESS);
        let obj = object::address_to_object<RescuableState>(obj_address);
        (signer, obj)
    }

    #[test_only]
    fun setup_fa(obj_address: address, amount: u64): (signer, Object<Metadata>) {
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
        let metadata = fa_constructor_ref.object_from_constructor_ref<Metadata>();

        // Mint tokens and deposit to the object (simulating stuck tokens)
        let mint_ref = fungible_asset::generate_mint_ref(&fa_constructor_ref);
        let asset = mint_ref.mint(amount);
        primary_fungible_store::deposit(obj_address, asset);
        
        // Verify tokens are in the object
        assert_eq(primary_fungible_store::balance(obj_address, metadata), amount);
        (asset_creator, metadata)
    }

    #[test]
    fun rescuer__should_return_rescuer() {
        let (_, obj) = setup_rescuable();
        assert_eq(rescuer(obj), RESCUE_ADDRESS);
    }

    #[test]
    fun new__should_set_rescuer_state() {
        let (_, obj) = setup_rescuable();
        assert_eq(rescuer(obj), RESCUE_ADDRESS);
    }

    #[test, expected_failure(abort_code = 0x60001, location = Self)]
    fun new__should_fail_if_owner_role_not_created() {
        let constructor_ref = object::create_sticky_object(@0x10);

        new(&constructor_ref, RESCUE_ADDRESS);
    }

    #[test]
    fun update_rescuer__should_update_rescuer() {
        let (_, obj) = setup_rescuable();
        let owner_signer = create_signer_for_test(OWNER_ADDRESS);
        update_rescuer(&owner_signer, obj, RESCUE_ADDRESS_2);
        assert_eq(rescuer(obj), RESCUE_ADDRESS_2);

        // Verify event was emitted
        assert_eq(event::was_event_emitted(&RescuerChanged {
            obj_address: obj.object_address(),
            new_rescuer: RESCUE_ADDRESS_2,
        }), true);
    }

    #[test, expected_failure(abort_code = aptos_extensions::ownable::ENOT_OWNER)]
    fun update_rescuer__should_fail_if_caller_is_not_owner() {
        let (_, obj) = setup_rescuable();
        let caller = create_signer_for_test(RANDOM_ADDRESS);
        update_rescuer(&caller, obj, RESCUE_ADDRESS_2);
    }

    #[test, expected_failure(abort_code = 0x10003, location = Self)]
    fun update_rescuer__should_fail_if_new_rescuer_is_same_as_old() {
        let (_, obj) = setup_rescuable();
        let owner_signer = create_signer_for_test(OWNER_ADDRESS);
        update_rescuer(&owner_signer, obj, RESCUE_ADDRESS);
    }

    #[test]
    fun rescue_fungible_asset__should_rescue_tokens() {        
        // Setup rescuable object
        let (obj_signer, rescuable_obj) = setup_rescuable();
        let obj_address = signer::address_of(&obj_signer);
        let amount = 1000000u64;

        // Setup fungible asset
        let (_, metadata) = setup_fa(obj_address, amount);

        // Rescue the tokens
        let rescuer_signer = create_signer_for_test(RESCUE_ADDRESS);
        rescue_fungible_asset(&rescuer_signer, rescuable_obj, metadata, RANDOM_ADDRESS, amount);
        
        // Verify tokens were rescued
        assert_eq(primary_fungible_store::balance(obj_address, metadata), 0);
        assert_eq(primary_fungible_store::balance(RANDOM_ADDRESS, metadata), amount);
    }

    #[test, expected_failure(abort_code = 0x50002, location = Self)]
    fun rescue_fungible_asset__should_fail_if_not_rescuer() {
        let (_, rescuable_obj) = setup_rescuable();
        
        // Create a test token
        let token_creator = create_signer_for_test(@0x9999);
        let fa_constructor_ref = object::create_named_object(&token_creator, b"TestToken");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &fa_constructor_ref,
            option::none(),
            utf8(b"Test Token"),
            utf8(b"TEST"),
            8,
            utf8(b""),
            utf8(b""),
        );
        let token_metadata = fa_constructor_ref.object_from_constructor_ref<Metadata>();
        
        // Try to rescue with non-rescuer (should fail)
        let non_rescuer = create_signer_for_test(RANDOM_ADDRESS);
        rescue_fungible_asset(&non_rescuer, rescuable_obj, token_metadata, RANDOM_ADDRESS, 100);
    }

    #[test, expected_failure(abort_code = 0x10004, location = aptos_framework::fungible_asset)]
    fun rescue_fungible_asset__should_fail_if_amount_insufficient() {
        let (obj_signer, rescuable_obj) = setup_rescuable();
        let obj_address = signer::address_of(&obj_signer);
        let (_, metadata) = setup_fa(obj_address, 10);

        // Rescue the tokens
        let rescuer_signer = create_signer_for_test(RESCUE_ADDRESS);
        rescue_fungible_asset(&rescuer_signer, rescuable_obj, metadata, RANDOM_ADDRESS, 1000);
    }

    #[test]
    fun destroy__should_destroy_rescuer_state() {
        let (signer, obj) = setup_rescuable();
        let obj_address = obj.object_address();
        destroy(&signer);
        assert_eq(object::object_exists<RescuableState>(obj_address), false);

        // Verify event was emitted
        assert_eq(event::was_event_emitted(&RescuableStateDestroyed {
            obj_address,
        }), true);
    }
}
