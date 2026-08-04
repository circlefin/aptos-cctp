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

module token_messenger_minter_v2::state {
    // Built-in Modules
    use std::bcs;
    use aptos_std::aptos_hash;
    use aptos_std::from_bcs;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_framework::object;
    use aptos_extensions::pausable::PauseState;

    // Package Modules
    use aptos_extensions::pausable;
    #[test_only]
    use std::signer;
    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_extensions::ownable;
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;

    // Constants
    const SEED_NAME: vector<u8> = b"TokenMessengerMinter";

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct State has key {
        message_body_version: u32,
        remote_token_messengers: BigOrderedMap<u32, address>,
        burn_limits_per_message: BigOrderedMap<address, u64>,
        remote_tokens_to_local_tokens: BigOrderedMap<address, address>,

        // Admin Roles
        token_controller: address                   // Controls remote resources and burn limits
    }

    package fun init_state(
        admin: &signer,
        message_body_version: u32,
    ) {
        move_to(
            admin,
            State {
                message_body_version,
                remote_token_messengers: big_ordered_map::new(),
                remote_tokens_to_local_tokens: big_ordered_map::new(),
                burn_limits_per_message: big_ordered_map::new(),

                // Admin Roles
                token_controller: @0x0,             // Token Controller gets initialized in its own module
            }
        );
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    package fun is_initialized(): bool {
        exists<State>(get_object_address())
    }

    package fun get_message_body_version(): u32 {
        borrow_global<State>(get_object_address()).message_body_version
    }

    package fun get_remote_token_messenger(domain: u32): address {
        *borrow_global<State>(get_object_address()).remote_token_messengers.borrow(&domain)
    }

    package fun is_remote_token_messenger_set_for_domain(
        domain: u32
    ): bool {
        borrow_global<State>(get_object_address()).remote_token_messengers.contains(&domain)
    }

    package fun get_max_burn_limit_per_message_for_token(token: address): (bool, u64) {
        let state = borrow_global<State>(get_object_address());
        if (state.burn_limits_per_message.contains(&token)) {
            (true, *state.burn_limits_per_message.borrow(&token))
        } else {
            (false, 0)
        }
    }

    package fun local_token_exists(remote_domain: u32, remote_token: address): bool {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        borrow_global<State>(get_object_address()).remote_tokens_to_local_tokens.contains(&key)
    }

    package fun get_local_token(remote_domain: u32, remote_token: address): address {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        *borrow_global<State>(get_object_address()).remote_tokens_to_local_tokens.borrow(&key)
    }

    package fun is_paused(): bool {
        pausable::is_paused(object::address_to_object<PauseState>(get_object_address()))
    }

    package fun get_token_controller(): address {
        borrow_global<State>(get_object_address()).token_controller
    }

    package fun get_num_remote_token_messengers(): u64 {
        borrow_global<State>(get_object_address()).remote_token_messengers.compute_length()
    }

    package fun get_num_linked_tokens(): u64 {
        borrow_global<State>(get_object_address()).remote_tokens_to_local_tokens.compute_length()
    }

    package fun get_object_address(): address {
        object::create_object_address(&@token_messenger_minter_v2, SEED_NAME)
    }

    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    package fun add_remote_token_messenger(domain: u32, token_messenger: address) {
        borrow_global_mut<State>(get_object_address()).remote_token_messengers.add(domain, token_messenger);
    }

    package fun remove_remote_token_messenger(domain: u32): address {
        borrow_global_mut<State>(get_object_address()).remote_token_messengers.remove(&domain)
    }

    package fun add_local_token_for_remote_token(
        remote_domain: u32,
        remote_token: address,
        local_token: address
    ) {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens.add(key, local_token);
    }

    package fun remove_local_token_for_remote_token(
        remote_domain: u32,
        remote_token: address
    ): address {
        let key = hash_remote_domain_and_token(remote_domain, remote_token);
        borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens.remove(&key)
    }

    package fun set_max_burn_limit_per_message_for_token(token: address, limit: u64) {
        borrow_global_mut<State>(get_object_address()).burn_limits_per_message.upsert(token, limit);
    }

    package fun set_token_controller(token_controller: address) {
        borrow_global_mut<State>(get_object_address()).token_controller = token_controller;
    }

    // -----------------------------
    // ----- Private Functions -----
    // -----------------------------

    /// Create hash based on "{remote_domain}{token}"
    fun hash_remote_domain_and_token(remote_domain: u32, token: address): address {
        let key = bcs::to_bytes(&remote_domain);
        key.append(bcs::to_bytes(&token));
        let hash = aptos_hash::keccak256(key);
        from_bcs::to_address(hash)
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    #[test_only]
    public fun init_test_state(caller: &signer) {
        init_test_state_and_get_signer(caller);
    }

    #[test_only]
    /// Test-only helper that initializes state and returns the TMM object signer.
    /// This allows other modules (like handler_registry) to initialize on the same object.
    public fun init_test_state_and_get_signer(caller: &signer): signer {
        let resource_account_address = account::create_resource_address(&@deployer, b"test_seed_tmm");
        let resource_account_signer = create_signer_for_test(resource_account_address);
        let constructor_ref = object::create_named_object(&resource_account_signer, SEED_NAME);
        let tmm_signer = constructor_ref.generate_signer();
        init_state(&tmm_signer, 1);
        ownable::new(&tmm_signer, signer::address_of(caller));
        pausable::new(&tmm_signer, signer::address_of(caller));
        tmm_signer
    }

    #[test_only]
    public fun set_paused(pauser: &signer) {
        pausable::test_pause(pauser, object::address_to_object<PauseState>(get_object_address()));
    }

    #[test_only]
    public fun set_message_body_version(message_body_version: u32) {
        borrow_global_mut<State>(get_object_address()).message_body_version = message_body_version;
    }

    // -----------------------------
    // ---------- Getters ----------
    // -----------------------------

    #[test(owner = @token_messenger_minter_v2)]
    fun test_is_initialized(owner: &signer) {
        init_test_state(owner);
        assert!(is_initialized());
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_get_message_body_version(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_message_body_version(), 1);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_get_remote_token_messenger(owner: &signer) {
        init_test_state(owner);
        let domain = 4;
        let token_messenger = @0xfab;
        borrow_global_mut<State>(get_object_address()).remote_token_messengers.add(domain, token_messenger);
        assert_eq(get_remote_token_messenger(domain), token_messenger);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_is_remote_token_messenger_set_for_domain(owner: &signer) {
        init_test_state(owner);
        let domain = 4;
        let token_messenger = @0xfab;
        borrow_global_mut<State>(get_object_address()).remote_token_messengers.add(domain, token_messenger);
        assert!(is_remote_token_messenger_set_for_domain(domain), 0);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_get_burn_limit_per_message_for_token(owner: &signer) {
        init_test_state(owner);
        let token = @0xfab;
        let expected_limit = 300;
        borrow_global_mut<State>(get_object_address()).burn_limits_per_message.add(token, expected_limit);
        let (exists, limit) = get_max_burn_limit_per_message_for_token(token);
        assert!(exists, 0);
        assert_eq(limit, expected_limit);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_is_remote_token(owner: &signer) {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens.add(
            hash_remote_domain_and_token(remote_domain, remote_token),
            local_token
        );
        assert!(local_token_exists(remote_domain, remote_token), 0);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_get_remote_token(owner: &signer) {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens.add(
            hash_remote_domain_and_token(remote_domain, remote_token),
            local_token
        );
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_is_paused(owner: &signer) {
        init_test_state(owner);
        assert!(!is_paused());
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_get_token_controller(owner: &signer) {
        init_test_state(owner);
        assert_eq(get_token_controller(), @0x0);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_get_num_remote_token_messengers(owner: &signer) {
        init_test_state(owner);
        let domain = 4;
        let token_messenger = @0xfab;
        borrow_global_mut<State>(get_object_address()).remote_token_messengers.add(domain, token_messenger);
        assert_eq(get_num_remote_token_messengers(), 1);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_hash_remote_domain_and_token(owner: &signer) {
        init_test_state(owner);
        let hash = hash_remote_domain_and_token(4, @0xfac);
        assert_eq(hash, @0x8ae28a8d79ea231bafe63fb643c45dce060b33a1c2e122d161c4d8b75997436);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_get_num_linked_tokens(owner: &signer) {
        init_test_state(owner);
        borrow_global_mut<State>(get_object_address()).remote_tokens_to_local_tokens.add(@0x100, @0x101);
        assert_eq(get_num_linked_tokens(), 1)
    }


    // -----------------------------
    // ---------- Setters ----------
    // -----------------------------

    #[test(owner = @token_messenger_minter_v2)]
    fun test_add_remote_token_messenger(owner: &signer) {
        init_test_state(owner);
        let domain = 5;
        let token_messenger = @0xcaf;
        add_remote_token_messenger(domain, token_messenger);
        assert_eq(get_remote_token_messenger(domain), token_messenger);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_remove_remote_token_messenger(owner: &signer) {
        init_test_state(owner);
        let domain = 5;
        let token_messenger = @0xcaf;
        add_remote_token_messenger(domain, token_messenger);
        assert_eq(get_remote_token_messenger(domain), token_messenger);

        remove_remote_token_messenger(domain);
        assert!(!is_remote_token_messenger_set_for_domain(domain), 0)
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_add_remote_token(owner: &signer) {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_remove_remote_token(owner: &signer) {
        init_test_state(owner);
        let remote_token = @0xfab;
        let remote_domain = 4;
        let local_token = @0xfac;
        add_local_token_for_remote_token(remote_domain, remote_token, local_token);
        assert!(get_local_token(remote_domain, remote_token) == local_token, 0);

        remove_local_token_for_remote_token(remote_domain, remote_token);
        assert!(!local_token_exists(remote_domain, remote_token), 0);
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_set_max_burn_limit_for_token(owner: &signer) {
        init_test_state(owner);
        let token = @0xcaf;
        let limit = 300;
        set_max_burn_limit_per_message_for_token(token, limit);
        assert!(
            *borrow_global<State>(get_object_address()).burn_limits_per_message.borrow(&token) == limit,
            0
        )
    }

    #[test(owner = @token_messenger_minter_v2)]
    fun test_set_token_controller(owner: &signer) {
        init_test_state(owner);
        let new_token_controller = @0xfad;
        set_token_controller(new_token_controller);
        assert_eq(get_token_controller(), new_token_controller);
    }
}
