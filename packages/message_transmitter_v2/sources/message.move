/// Copyright (c) 2026, Circle Internet Group, Inc.
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

/// Module for serializing outgoing and deserializing incoming v2 messages. Message is dynamically sized.
///
/// Message is structured in the following order:
/// -----------------------------------------------------------
/// Field                        Bytes      Type       Index
/// version                      4          uint32     0
/// source_domain                4          uint32     4
/// destination_domain           4          uint32     8
/// nonce                        32         bytes32    12
/// sender                       32         bytes32    44
/// recipient                    32         bytes32    76
/// destination_caller           32         bytes32    108
/// min_finality_threshold       4          uint32     140
/// finality_threshold_executed  4          uint32     144
/// message_body                 dynamic    bytes      148
/// -----------------------------------------------------------
module message_transmitter_v2::message {
    // Built-in Modules
    use std::error;
    use std::vector;

    // Package Modules
    use message_transmitter_v2::serialize;
    use message_transmitter_v2::deserialize;

    // === Constants ===

    // Field indices and lengths
    const VERSION_INDEX: u64 = 0;
    const SOURCE_DOMAIN_INDEX: u64 = 4;
    const DESTINATION_DOMAIN_INDEX: u64 = 8;
    const NONCE_INDEX: u64 = 12;
    const SENDER_INDEX: u64 = 44;
    const RECIPIENT_INDEX: u64 = 76;
    const DESTINATION_CALLER_INDEX: u64 = 108;
    const MIN_FINALITY_THRESHOLD_INDEX: u64 = 140;
    const FINALITY_THRESHOLD_EXECUTED_INDEX: u64 = 144;
    const MESSAGE_BODY_INDEX: u64 = 148;

    const VERSION_LEN: u64 = 4;
    const SOURCE_DOMAIN_LEN: u64 = 4;
    const DESTINATION_DOMAIN_LEN: u64 = 4;
    const NONCE_LEN: u64 = 32;
    const SENDER_LEN: u64 = 32;
    const RECIPIENT_LEN: u64 = 32;
    const DESTINATION_CALLER_LEN: u64 = 32;
    const MIN_FINALITY_THRESHOLD_LEN: u64 = 4;
    const FINALITY_THRESHOLD_EXECUTED_LEN: u64 = 4;

    // Default values
    const EMPTY_NONCE: u256 = 0;
    const EMPTY_FINALITY_THRESHOLD_EXECUTED: u32 = 0;

    // === Errors ===

    /// Invalid message format
    const EINVALID_FORMAT: u64 = 1;

    // === Public Functions ===

    public fun get_message_version(message: &vector<u8>): u32 {
        deserialize::deserialize_u32(message, VERSION_INDEX, VERSION_LEN)
    }

    public fun get_src_domain_id(message: &vector<u8>): u32 {
        deserialize::deserialize_u32(message, SOURCE_DOMAIN_INDEX, SOURCE_DOMAIN_LEN)
    }

    public fun get_destination_domain_id(message: &vector<u8>): u32 {
        deserialize::deserialize_u32(message, DESTINATION_DOMAIN_INDEX, DESTINATION_DOMAIN_LEN)
    }

    public fun get_nonce(message: &vector<u8>): u256 {
        deserialize::deserialize_u256(message, NONCE_INDEX, NONCE_LEN)
    }

    public fun get_sender_address(message: &vector<u8>): address {
        deserialize::deserialize_address(message, SENDER_INDEX, SENDER_LEN)
    }

    public fun get_recipient_address(message: &vector<u8>): address {
        deserialize::deserialize_address(message, RECIPIENT_INDEX, RECIPIENT_LEN)
    }

    public fun get_destination_caller(message: &vector<u8>): address {
        deserialize::deserialize_address(message, DESTINATION_CALLER_INDEX, DESTINATION_CALLER_LEN)
    }

    public fun get_min_finality_threshold(message: &vector<u8>): u32 {
        deserialize::deserialize_u32(message, MIN_FINALITY_THRESHOLD_INDEX, MIN_FINALITY_THRESHOLD_LEN)
    }

    public fun get_finality_threshold_executed(message: &vector<u8>): u32 {
        deserialize::deserialize_u32(message, FINALITY_THRESHOLD_EXECUTED_INDEX, FINALITY_THRESHOLD_EXECUTED_LEN)
    }

    public fun get_message_body(message: &vector<u8>): vector<u8> {
        message.slice(MESSAGE_BODY_INDEX, message.length())
    }

    public fun serialize(
        version: u32,
        source_domain: u32,
        destination_domain: u32,
        sender: address,
        recipient: address,
        destination_caller: address,
        min_finality_threshold: u32,
        message_body: &vector<u8>
    ): vector<u8> {
        let result = vector::empty<u8>();
        result.append(serialize::serialize_u32(version));
        result.append(serialize::serialize_u32(source_domain));
        result.append(serialize::serialize_u32(destination_domain));
        result.append(serialize::serialize_u256(EMPTY_NONCE));
        result.append(serialize::serialize_address(sender));
        result.append(serialize::serialize_address(recipient));
        result.append(serialize::serialize_address(destination_caller));
        result.append(serialize::serialize_u32(min_finality_threshold));
        result.append(serialize::serialize_u32(EMPTY_FINALITY_THRESHOLD_EXECUTED));
        result.append(*message_body);
        result
    }

    // Bytes message should contain all the data required for message transmitter. Message body is optional
    public fun validate_message(message: &vector<u8>) {
        assert!(message.length() >= MESSAGE_BODY_INDEX, error::invalid_argument(EINVALID_FORMAT));
    }

    // === Test-only Functions ===

    #[test_only]
    use aptos_extensions::test_utils::assert_eq;

    #[test_only] const VERSION: u32 = 1;
    #[test_only] const SOURCE_DOMAIN: u32 = 0;
    #[test_only] const DESTINATION_DOMAIN: u32 = 1;
    #[test_only] const SENDER: address = @0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5;
    #[test_only] const RECIPIENT: address = @0xeb08f243e5d3fcff26a9e38ae5520a669f4019d0;
    #[test_only] const DESTINATION_CALLER: address = @0x1f26414439C8D03FC4b9CA912CeFd5Cb508C9605;
    #[test_only] const MIN_FINALITY_THRESHOLD: u32 = 1000;
    #[test_only] const MESSAGE_BODY: vector<u8> = x"000000000000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000001f26414439c8d03fc4b9ca912cefd5cb508c960500000000000000000000000000000000000000000000000000000000000004be0000000000000000000000003b61abee91852714e4e99b09a1af3e9c13893ef1";

    #[test_only]
    /// Creates a test message with v2 format by serializing directly
    fun get_test_message(): vector<u8> {
        serialize(
            VERSION,
            SOURCE_DOMAIN,
            DESTINATION_DOMAIN,
            SENDER,
            RECIPIENT,
            DESTINATION_CALLER,
            MIN_FINALITY_THRESHOLD,
            &MESSAGE_BODY
        )
    }

    #[test]
    fun test_get_message_version() {
        let message = get_test_message();
        assert_eq(get_message_version(&message), VERSION);
    }

    #[test]
    fun test_get_src_domain_id() {
        let message = get_test_message();
        assert_eq(get_src_domain_id(&message), SOURCE_DOMAIN);
    }

    #[test]
    fun test_get_destination_domain_id() {
        let message = get_test_message();
        assert_eq(get_destination_domain_id(&message), DESTINATION_DOMAIN);
    }

    #[test]
    fun test_get_nonce() {
        let message = get_test_message();
        let nonce = get_nonce(&message);
        assert_eq(nonce, EMPTY_NONCE);
    }

    #[test]
    fun test_get_nonce_non_empty() {
        let message = get_test_message();
        let non_empty_nonce: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111;
        let nonce_bytes = serialize::serialize_u256(non_empty_nonce);

        let i = 0;
        while (i < NONCE_LEN) {
            *message.borrow_mut(NONCE_INDEX + i) = nonce_bytes[i];
            i += 1;
        };

        let nonce = get_nonce(&message);
        assert_eq(nonce, non_empty_nonce);
    }

    #[test]
    fun test_get_sender_address() {
        let message = get_test_message();
        assert_eq(get_sender_address(&message), SENDER);
    }

    #[test]
    fun test_get_recipient_address() {
        let message = get_test_message();
        assert_eq(get_recipient_address(&message), RECIPIENT);
    }

    #[test]
    fun test_get_destination_caller() {
        let message = get_test_message();
        assert_eq(get_destination_caller(&message), DESTINATION_CALLER);
    }

    #[test]
    fun test_get_min_finality_threshold() {
        let message = get_test_message();
        assert_eq(get_min_finality_threshold(&message), MIN_FINALITY_THRESHOLD);
    }

    #[test]
    fun test_get_finality_threshold_executed() {
        let message = get_test_message();
        assert_eq(get_finality_threshold_executed(&message), 0);
    }

    #[test]
    fun test_get_finality_threshold_executed_non_empty() {
        let message = get_test_message();
        let non_empty_threshold: u32 = 1000;
        let threshold_bytes = serialize::serialize_u32(non_empty_threshold);

        let i = 0;
        while (i < FINALITY_THRESHOLD_EXECUTED_LEN) {
            *message.borrow_mut(FINALITY_THRESHOLD_EXECUTED_INDEX + i) = threshold_bytes[i];
            i += 1;
        };

        assert_eq(get_finality_threshold_executed(&message), non_empty_threshold);
    }

    #[test]
    fun test_get_message_body() {
        let message = get_test_message();
        assert_eq(get_message_body(&message), MESSAGE_BODY);
    }

    #[test]
    fun test_get_message_body_empty_message_body() {
        let empty_body = vector::empty<u8>();
        let message = serialize(
            VERSION,
            SOURCE_DOMAIN,
            DESTINATION_DOMAIN,
            SENDER,
            RECIPIENT,
            DESTINATION_CALLER,
            MIN_FINALITY_THRESHOLD,
            &empty_body
        );
        assert_eq(get_message_body(&message), empty_body);
    }

    #[test]
    fun test_serialize() {
        let formatted = serialize(
            VERSION,
            SOURCE_DOMAIN,
            DESTINATION_DOMAIN,
            SENDER,
            RECIPIENT,
            DESTINATION_CALLER,
            MIN_FINALITY_THRESHOLD,
            &MESSAGE_BODY
        );

        assert_eq(get_message_version(&formatted), VERSION);
        assert_eq(get_src_domain_id(&formatted), SOURCE_DOMAIN);
        assert_eq(get_destination_domain_id(&formatted), DESTINATION_DOMAIN);
        assert_eq(get_nonce(&formatted), EMPTY_NONCE);
        assert_eq(get_sender_address(&formatted), SENDER);
        assert_eq(get_recipient_address(&formatted), RECIPIENT);
        assert_eq(get_destination_caller(&formatted), DESTINATION_CALLER);
        assert_eq(get_min_finality_threshold(&formatted), MIN_FINALITY_THRESHOLD);
        assert_eq(get_finality_threshold_executed(&formatted), EMPTY_FINALITY_THRESHOLD_EXECUTED);
        assert_eq(get_message_body(&formatted), MESSAGE_BODY);
    }

    #[test]
    fun test_validate_message_valid() {
        let message = get_test_message();
        validate_message(&message);
    }

    #[test]
    fun test_validate_message_valid_empty_message_body() {
        let empty_body = vector::empty<u8>();
        let message = serialize(
            VERSION,
            SOURCE_DOMAIN,
            DESTINATION_DOMAIN,
            SENDER,
            RECIPIENT,
            DESTINATION_CALLER,
            MIN_FINALITY_THRESHOLD,
            &empty_body
        );
        validate_message(&message);
    }

    #[test, expected_failure(abort_code = 0x10001, location = Self)]
    fun test_validate_message_not_sufficient_length() {
        let invalid_message = vector[1, 2, 3, 4, 5];
        validate_message(&invalid_message);
    }
}
