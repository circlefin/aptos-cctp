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

module token_messenger_minter_v2::fee_controller {
    use std::error;
    use std::signer;
    use aptos_framework::event;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_extensions::ownable;
    use token_messenger_minter_v2::state;

    // === Errors ===

    /// Caller is not the min fee controller
    const ENOT_MIN_FEE_CONTROLLER: u64 = 1;
    /// Invalid fee recipient address
    const EINVALID_FEE_RECIPIENT_ADDRESS: u64 = 2;
    /// New fee recipient is the same as the old one
    const ENEW_FEE_RECIPIENT_SAME_AS_OLD: u64 = 3;
    /// Invalid min fee controller address
    const EINVALID_MIN_FEE_CONTROLLER_ADDRESS: u64 = 4;
    /// New min fee controller is the same as the old one
    const ENEW_MIN_FEE_CONTROLLER_SAME_AS_OLD: u64 = 5;
    /// Min fee is too high
    const EMIN_FEE_TOO_HIGH: u64 = 6;
    /// Amount is too low
    const EAMOUNT_TOO_LOW: u64 = 7;

    // === Constants ===

    const MIN_FEE_MULTIPLIER: u256 = 10000000; // 1/1000th basis point precision

    // === Structs ===

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// The fee controller state
    struct FeeControllerState has key {
        fee_recipient: address,
        min_fee_controller: address,
        min_fee: BigOrderedMap<address, u256>,
    }

    // === Events ===

    #[event]
    /// Emitted when fee recipient is set
    struct FeeRecipientSet has drop, store {
        address: address,
    }

    #[event]
    /// Emitted when min fee controller is set
    struct MinFeeControllerSet has drop, store {
        address: address,
    }

    #[event]
    /// Emitted when min fee is set
    struct MinFeeSet has drop, store {
        token_address: address,
        min_fee: u256,
    }

    /// Calculates the minimum fee amount for a given amount and burn token
    /// Returns 0 if the fee is not enabled for the burn token
    /// Returns 1 if the minimum fee amount after applying the fee multiplier is 0
    /// Returns the minimum fee amount otherwise
    package fun get_min_fee_amount(amount: u256, burn_token: address): u256 {
        let min_fee = get_min_fee(burn_token);
        if (min_fee == 0) {
            return min_fee
        };

        assert!(amount > 1, error::invalid_argument(EAMOUNT_TOO_LOW));

        let min_fee_amount = (amount * min_fee) / MIN_FEE_MULTIPLIER;

        if (min_fee_amount == 0) {
            return 1
        };

        min_fee_amount
    }

    // === View-only functions ===

    #[view]
    public fun get_fee_recipient(): address {
        borrow_global<FeeControllerState>(state::get_object_address()).fee_recipient
    }

    #[view]
    public fun get_min_fee_controller(): address {
        borrow_global<FeeControllerState>(state::get_object_address()).min_fee_controller
    }

    #[view]
    public fun get_min_fee(token_address: address): u256 {
        let fee_controller_state = borrow_global<FeeControllerState>(state::get_object_address());
        if (fee_controller_state.min_fee.contains(&token_address)) {
            *fee_controller_state.min_fee.borrow(&token_address)
        } else {
            0
        }
    }

    /// Asserts that the caller is the min fee controller
    fun assert_is_min_fee_controller(caller: &signer) {
        let fee_controller_state = borrow_global<FeeControllerState>(state::get_object_address());
        assert!(
            signer::address_of(caller) == fee_controller_state.min_fee_controller,
            error::permission_denied(ENOT_MIN_FEE_CONTROLLER)
        );
    }

    // === Write functions ===

    /// Creates and inits a new fee controller state
    package fun new(signer: &signer, fee_recipient: address, min_fee_controller: address) {
        assert!(fee_recipient != @0x0, error::invalid_argument(EINVALID_FEE_RECIPIENT_ADDRESS));
        assert!(min_fee_controller != @0x0, error::invalid_argument(EINVALID_MIN_FEE_CONTROLLER_ADDRESS));
        move_to(signer, FeeControllerState {
            fee_recipient,
            min_fee_controller,
            min_fee: big_ordered_map::new(),
        });
    }

    /// Sets the fee recipient address - Owner only
    package entry fun set_fee_recipient(caller: &signer, new_fee_recipient: address) {
        assert!(new_fee_recipient != @0x0, error::invalid_argument(EINVALID_FEE_RECIPIENT_ADDRESS));

        let obj_address = state::get_object_address();
        ownable::assert_is_owner(caller, obj_address);

        let fee_controller_state = borrow_global_mut<FeeControllerState>(obj_address);
        assert!(fee_controller_state.fee_recipient != new_fee_recipient, error::invalid_argument(ENEW_FEE_RECIPIENT_SAME_AS_OLD));

        fee_controller_state.fee_recipient = new_fee_recipient;
        event::emit(FeeRecipientSet { address: new_fee_recipient });
    }

    /// Sets the min fee controller address - Owner only
    entry fun set_min_fee_controller(caller: &signer, new_min_fee_controller: address) {
        assert!(new_min_fee_controller != @0x0, error::invalid_argument(EINVALID_MIN_FEE_CONTROLLER_ADDRESS));

        let obj_address = state::get_object_address();
        ownable::assert_is_owner(caller, obj_address);

        let fee_controller_state = borrow_global_mut<FeeControllerState>(obj_address);
        assert!(fee_controller_state.min_fee_controller != new_min_fee_controller, error::invalid_argument(ENEW_MIN_FEE_CONTROLLER_SAME_AS_OLD));

        fee_controller_state.min_fee_controller = new_min_fee_controller;
        event::emit(MinFeeControllerSet { address: new_min_fee_controller });
    }

    /// Sets the minimum fee for a token or updates the minimum fee if it already exists - Min Fee Controller only
    entry fun set_min_fee(caller: &signer, token_address: address, min_fee: u256) {
        assert_is_min_fee_controller(caller);

        assert!(min_fee < MIN_FEE_MULTIPLIER, error::invalid_argument(EMIN_FEE_TOO_HIGH));

        let fee_controller_state = borrow_global_mut<FeeControllerState>(state::get_object_address());
        fee_controller_state.min_fee.upsert(token_address, min_fee);

        event::emit(MinFeeSet {
            token_address,
            min_fee,
        });
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
    const RANDOM_ADDRESS: address = @0x7777;
    #[test_only]
    const OWNER_ADDRESS: address = @0x1111;
    #[test_only]
    const FEE_RECIPIENT_ADDRESS: address = @0x2222;
    #[test_only]
    const FEE_RECIPIENT_ADDRESS_2: address = @0x3333;
    #[test_only]
    const MIN_FEE_CONTROLLER_ADDRESS: address = @0x4444;
    #[test_only]
    const MIN_FEE_CONTROLLER_ADDRESS_2: address = @0x5555;
    #[test_only]
    const TOKEN_ADDRESS: address = @0x6666;
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
    public fun set_min_fee_for_testing(token_address: address, min_fee: u256) {
        let fee_controller_state = borrow_global_mut<FeeControllerState>(state::get_object_address());
        fee_controller_state.min_fee.upsert(token_address, min_fee);
    }

    #[test_only]
    public fun set_fee_recipient_for_testing(new_fee_recipient: address) {
        let fee_controller_state = borrow_global_mut<FeeControllerState>(state::get_object_address());
        fee_controller_state.fee_recipient = new_fee_recipient;
    }

    #[test_only]
    fun setup() {
        let signer = &create_resource();
        new(signer, FEE_RECIPIENT_ADDRESS, MIN_FEE_CONTROLLER_ADDRESS);
    }

    #[test, expected_failure(abort_code = 0x10002, location = Self)]
    fun new__should_fail_with_zero_address_fee_recipient() {
        let signer = &create_resource();
        new(signer, @0x0, MIN_FEE_CONTROLLER_ADDRESS);
    }

    #[test, expected_failure(abort_code = 0x10004, location = Self)]
    fun new__should_fail_with_zero_address_min_fee_controller() {
        let signer = &create_resource();
        new(signer, FEE_RECIPIENT_ADDRESS, @0x0);
    }

    #[test]
    fun get_min_fee_amount__should_get_min_fee_as_zero_for_token_for_which_min_fee_is_not_set() {
        setup();

        assert_eq(get_min_fee_amount(10, RANDOM_ADDRESS), 0);
    }

    #[test]
    fun get_min_fee_amount__should_return_one_if_calculated_min_fee_amount_is_less_than_one() {
        setup();

        set_min_fee_for_testing(TOKEN_ADDRESS, 100000);

        assert_eq(get_min_fee_amount(50, TOKEN_ADDRESS), 1); // (50 * 100000) / 10000000 = 0.5
    }

    #[test]
    fun get_min_fee_amount__should_calculate_correct_min_fee_amount() {
        setup();

        set_min_fee_for_testing(TOKEN_ADDRESS, 100000);

        assert_eq(get_min_fee_amount(1000000, TOKEN_ADDRESS), 10000); // (1000000 * 100000) / 10000000 = 10000
    }

    #[test]
    fun get_min_fee__should_return_zero_when_not_set() {
        setup();
        let min_fee = get_min_fee(TOKEN_ADDRESS);
        assert_eq(min_fee, 0);
    }

    #[test, expected_failure(abort_code = 0x10007, location = Self)]
    fun get_min_fee_amount__should_throw_error_if_amount_is_zero() {
        setup();

        set_min_fee_for_testing(TOKEN_ADDRESS, 100000);

        get_min_fee_amount(0, TOKEN_ADDRESS);
    }

    #[test, expected_failure(abort_code = 0x10007, location = Self)]
    fun get_min_fee_amount__should_throw_error_if_amount_is_one() {
        setup();

        set_min_fee_for_testing(TOKEN_ADDRESS, 100000);

        get_min_fee_amount(1, TOKEN_ADDRESS);
    }

    #[test]
    fun set_min_fee__should_set_min_fee_as_min_fee_controller() {
        setup();

        let min_fee_controller = &create_signer_for_test(MIN_FEE_CONTROLLER_ADDRESS);
        let test_min_fee = 100000;
        set_min_fee(min_fee_controller, TOKEN_ADDRESS, test_min_fee);

        assert_eq(get_min_fee(TOKEN_ADDRESS), test_min_fee);
        assert_eq(
            event::was_event_emitted(&MinFeeSet { token_address: TOKEN_ADDRESS, min_fee: test_min_fee }),
            true
        );
    }

    #[test]
    fun set_min_fee__should_update_existing_min_fee() {
        setup();

        let min_fee_controller = &create_signer_for_test(MIN_FEE_CONTROLLER_ADDRESS);
        let initial_min_fee = 100000;
        set_min_fee(min_fee_controller, TOKEN_ADDRESS, initial_min_fee);
        assert_eq(get_min_fee(TOKEN_ADDRESS), initial_min_fee);

        let updated_min_fee = 200000;
        set_min_fee(min_fee_controller, TOKEN_ADDRESS, updated_min_fee);

        assert_eq(get_min_fee(TOKEN_ADDRESS), updated_min_fee);
        assert_eq(
            event::was_event_emitted(&MinFeeSet { token_address: TOKEN_ADDRESS, min_fee: updated_min_fee }),
            true
        );
    }

    #[test, expected_failure(abort_code = 0x50001, location = Self)]
    fun set_min_fee__should_not_set_min_fee_if_not_min_fee_controller() {
        setup();

        let not_min_fee_controller = &create_signer_for_test(RANDOM_ADDRESS);
        set_min_fee(not_min_fee_controller, TOKEN_ADDRESS, 100000);
    }

    #[test, expected_failure(abort_code = 0x10006, location = Self)]
    fun set_min_fee__should_not_set_min_fee_above_maximum_limit() {
        setup();

        let min_fee_controller = &create_signer_for_test(MIN_FEE_CONTROLLER_ADDRESS);
        set_min_fee(min_fee_controller, TOKEN_ADDRESS, MIN_FEE_MULTIPLIER);
    }

    #[test]
    fun set_min_fee_controller__should_set_min_fee_controller_as_owner() {
        setup();

        let owner = &create_signer_for_test(OWNER_ADDRESS);
        set_min_fee_controller(owner, MIN_FEE_CONTROLLER_ADDRESS_2);

        assert_eq(get_min_fee_controller(), MIN_FEE_CONTROLLER_ADDRESS_2);
        assert_eq(event::was_event_emitted(&MinFeeControllerSet { address: MIN_FEE_CONTROLLER_ADDRESS_2 }), true);
    }

    #[test, expected_failure(abort_code = ownable::ENOT_OWNER)]
    fun set_min_fee_controller__should_not_set_min_fee_controller_if_not_owner() {
        setup();

        let not_owner = &create_signer_for_test(RANDOM_ADDRESS);
        set_min_fee_controller(not_owner, MIN_FEE_CONTROLLER_ADDRESS);
    }

    #[test, expected_failure(abort_code = 0x10004, location = Self)]
    fun set_min_fee_controller__should_not_set_min_fee_controller_to_zero_address() {
        setup();

        let owner = &create_signer_for_test(OWNER_ADDRESS);
        set_min_fee_controller(owner, @0x0);
    }

    #[test, expected_failure(abort_code = 0x10005, location = Self)]
    fun set_min_fee_controller__should_not_set_min_fee_controller_to_same_address() {
        setup();

        let owner = &create_signer_for_test(OWNER_ADDRESS);
        let fee_controller_state = borrow_global<FeeControllerState>(state::get_object_address());
        let current_min_fee_controller = fee_controller_state.min_fee_controller;
        set_min_fee_controller(owner, current_min_fee_controller);
    }

    #[test]
    fun set_fee_recipient__should_set_fee_recipient_as_owner() {
        setup();

        let owner = &create_signer_for_test(OWNER_ADDRESS);
        set_fee_recipient(owner, FEE_RECIPIENT_ADDRESS_2);

        assert_eq(get_fee_recipient(), FEE_RECIPIENT_ADDRESS_2);
        assert_eq(event::was_event_emitted(&FeeRecipientSet { address: FEE_RECIPIENT_ADDRESS_2 }), true);
    }

    #[test, expected_failure(abort_code = ownable::ENOT_OWNER)]
    fun set_fee_recipient__should_not_set_fee_recipient_if_not_owner() {
        setup();

        let not_owner = &create_signer_for_test(RANDOM_ADDRESS);
        set_fee_recipient(not_owner, FEE_RECIPIENT_ADDRESS_2);
    }

    #[test, expected_failure(abort_code = 0x10002, location = Self)]
    fun set_fee_recipient__should_not_set_fee_recipient_to_zero_address() {
        setup();

        let owner = &create_signer_for_test(OWNER_ADDRESS);
        set_fee_recipient(owner, @0x0);
    }

    #[test, expected_failure(abort_code = 0x10003, location = Self)]
    fun set_fee_recipient__should_not_set_fee_recipient_to_same_address() {
        setup();

        let owner = &create_signer_for_test(OWNER_ADDRESS);
        let fee_controller_state = borrow_global<FeeControllerState>(state::get_object_address());
        let current_fee_recipient = fee_controller_state.fee_recipient;

        set_fee_recipient(owner, current_fee_recipient);
    }
}
