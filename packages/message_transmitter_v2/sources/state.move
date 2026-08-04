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

module message_transmitter_v2::state {
    // Built-in Modules
    use std::error;
    use std::signer;
    use std::vector;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_framework::object;
    use aptos_extensions::ownable::OwnerRole;

    // Package Modules
    use aptos_extensions::ownable;

    // Constants
    const SEED_NAME: vector<u8> = b"MessageTransmitter";

    // Error Codes
    const EATTESTER_NOT_FOUND: u64 = 1;

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct State has key {
        local_domain: u32,
        version: u32,
        max_message_body_size: u64,
        // Key for used_nonces is 32 bytes
        used_nonces: BigOrderedMap<u256, bool>,
        signature_threshold: u64,

        // Admin Roles
        enabled_attesters: vector<address>,         // Authorized witnesses to bridge transactions
        attester_manager: address,                  // Manages attester state and configuration
    }

    package fun init_state(
        owner: &signer,
        object_signer: &signer,
        local_domain: u32,
        version: u32,
        max_message_body_size: u64
    ) {
        move_to(
            object_signer,
            State {
                local_domain,
                version,
                max_message_body_size,
                used_nonces: big_ordered_map::new(),
                signature_threshold: 1,

                // Admin Roles
                attester_manager: signer::address_of(owner),
                enabled_attesters: vector::empty(),
            }
        );
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    package fun is_initialized(): bool {
        exists<State>(get_object_address())
    }

    package fun get_local_domain(): u32 {
        borrow_global<State>(get_object_address()).local_domain
    }

    package fun get_version(): u32 {
        borrow_global<State>(get_object_address()).version
    }

    package fun get_max_message_body_size(): u64 {
        borrow_global<State>(get_object_address()).max_message_body_size
    }

    package fun is_nonce_used(nonce: u256): bool {
        borrow_global<State>(get_object_address()).used_nonces.contains(&nonce)
    }

    package fun get_signature_threshold(): u64 {
        borrow_global<State>(get_object_address()).signature_threshold
    }

    package fun get_enabled_attesters(): vector<address> {
        borrow_global<State>(get_object_address()).enabled_attesters
    }

    package fun get_num_enabled_attesters(): u64 {
        borrow_global<State>(get_object_address()).enabled_attesters.length()
    }

    package fun get_attester_manager(): address {
        borrow_global<State>(get_object_address()).attester_manager
    }

    package fun get_owner(): address {
        ownable::owner(object::address_to_object<OwnerRole>(get_object_address()))
    }

    package fun get_object_address(): address {
        object::create_object_address(&@message_transmitter_v2, SEED_NAME)
    }

    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    package fun set_max_message_body_size(max_message_body_size: u64) {
        borrow_global_mut<State>(get_object_address()).max_message_body_size = max_message_body_size
    }

    package fun set_nonce_used(nonce: u256) {
        borrow_global_mut<State>(get_object_address()).used_nonces.add(nonce, true);
    }

    package fun set_signature_threshold(signature_threshold: u64) {
        borrow_global_mut<State>(get_object_address()).signature_threshold = signature_threshold
    }

    package fun add_attester(attester: address) {
        borrow_global_mut<State>(get_object_address()).enabled_attesters.push_back(attester);
    }

    package fun remove_attester(attester: address) {
        let state = borrow_global_mut<State>(get_object_address());
        let (found, index) = state.enabled_attesters.index_of(&attester);
        assert!(found, error::not_found(EATTESTER_NOT_FOUND));
        state.enabled_attesters.remove(index);
    }

    package fun set_attester_manager(attester_manager: address) {
        borrow_global_mut<State>(get_object_address()).attester_manager = attester_manager
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    use aptos_framework::account::{Self, create_signer_for_test};
    #[test_only]
    use aptos_extensions::pausable::{Self, PauseState};
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;

    #[test_only]
    public fun init_test_state(caller: &signer) {
        let resource_account_address = account::create_resource_address(&@deployer, b"test_seed_mt");
        let resource_account_signer = create_signer_for_test(resource_account_address);
        let constructor_ref = object::create_named_object(&resource_account_signer, SEED_NAME);
        let signer = constructor_ref.generate_signer();
        init_state(caller, &signer, 9, 0, 256);
        ownable::new(&signer, signer::address_of(caller));
        pausable::new(&signer, signer::address_of(caller));
    }

    #[test_only]
    public fun set_paused(pauser: &signer) {
        pausable::test_pause(pauser, object::address_to_object<PauseState>(get_object_address()));
    }

    #[test_only]
    public fun set_owner(owner_address: address) {
        ownable::set_owner_for_testing(get_object_address(), owner_address);
    }

    #[test_only]
    public fun set_version(version: u32) {
        borrow_global_mut<State>(get_object_address()).version = version
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    #[test(owner = @message_transmitter_v2)]
    fun test_is_initialized(owner: &signer) {
        init_test_state(owner);
        assert!(is_initialized());
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_get_local_domain(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_local_domain(), 9);
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_get_version(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_version(), 0);
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_get_max_message_body_size(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_max_message_body_size(), 256);
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_is_nonce_used(owner: &signer) {
        init_test_state(owner);
        let key: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111;
        assert!(!is_nonce_used(key));
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_get_signature_threshold(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_signature_threshold(), 1);
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_get_attester_manager(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_attester_manager(), signer::address_of(owner));
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_get_enabled_attesters(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_enabled_attesters(), vector::empty());
    }

    #[test(owner = @message_transmitter_v2, attester = @0x1234)]
    fun test_get_num_enabled_attesters(owner: &signer, attester: &signer) {
        init_test_state(owner);
        let address = signer::address_of(attester);
        add_attester(address);
        assert_eq(get_num_enabled_attesters(), 1);
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_get_owner(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_owner(), signer::address_of(owner));
    }

    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    #[test(owner = @message_transmitter_v2)]
    fun test_set_max_message_body_size(owner: &signer) {
        init_test_state(owner);
        let max_message_body_size = 512;
        set_max_message_body_size(max_message_body_size);
        assert_eq(get_max_message_body_size(), max_message_body_size);
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_set_nonce_used(owner: &signer) {
        init_test_state(owner);
        let key: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111;
        set_nonce_used(key);
        assert!(is_nonce_used(key));
    }

    #[test(owner = @message_transmitter_v2)]
    fun test_set_signature_threshold(owner: &signer) {
        init_test_state(owner);
        let signature_threshold = 10;
        set_signature_threshold(signature_threshold);
        assert_eq(get_signature_threshold(), signature_threshold);
    }

    #[test(owner = @message_transmitter_v2, manager = @0x1234)]
    fun test_set_attester_manager(owner: &signer, manager: &signer) {
        init_test_state(owner);
        let address = signer::address_of(manager);
        set_attester_manager(address);
        assert_eq(get_attester_manager(), address);
    }

    #[test(owner = @message_transmitter_v2, attester = @0x1234)]
    fun test_add_attester(owner: &signer, attester: &signer) {
        init_test_state(owner);
        let address = signer::address_of(attester);
        add_attester(address);
        assert!(get_enabled_attesters().contains(&address), 0);
    }

    #[test(owner = @message_transmitter_v2, attester = @0x1234)]
    fun test_remove_attester(owner: &signer, attester: &signer) {
        init_test_state(owner);
        let address = signer::address_of(attester);
        add_attester(address);
        remove_attester(address);
        assert!(!get_enabled_attesters().contains(&address), 0);
    }

    #[test(owner = @message_transmitter_v2, unknown_attester = @0x1234)]
    #[expected_failure(abort_code = 0x60001, location = Self)]
    fun test_remove_attester_attester_does_not_exist(owner: &signer, unknown_attester: &signer) {
        init_test_state(owner);
        let address = signer::address_of(unknown_attester);
        remove_attester(address);
    }
}
