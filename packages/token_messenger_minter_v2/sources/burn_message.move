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

/// Module for serializing outgoing and deserializing deposit for burn messages (V2)
///
/// Message is structured in the following order:
/// --------------------------------------------------
/// Field                 Bytes      Type       Index
/// version               4          uint32     0
/// burnToken             32         bytes32    4
/// mintRecipient         32         bytes32    36
/// amount                32         uint256    68
/// messageSender         32         bytes32    100
/// maxFee                32         uint256    132
/// feeExecuted           32         uint256    164
/// expirationBlock       32         uint256    196
/// hookData              dynamic    bytes      228
/// --------------------------------------------------
module token_messenger_minter_v2::burn_message {
    // Built-in Modules
    use std::error;
    use std::vector;

    // Package Modules
    use message_transmitter_v2::serialize;
    use message_transmitter_v2::deserialize;

    #[test_only]
    use aptos_extensions::test_utils::assert_eq;

    // Constants
    const VERSION_INDEX: u64 = 0;
    const VERSION_LEN: u64 = 4;
    const BURN_TOKEN_INDEX: u64 = 4;
    const BURN_TOKEN_LEN: u64 = 32;
    const MINT_RECIPIENT_INDEX: u64 = 36;
    const MINT_RECIPIENT_LEN: u64 = 32;
    const AMOUNT_INDEX: u64 = 68;
    const AMOUNT_LEN: u64 = 32;
    const MSG_SENDER_INDEX: u64 = 100;
    const MSG_SENDER_LEN: u64 = 32;
    const MAX_FEE_INDEX: u64 = 132;
    const MAX_FEE_LEN: u64 = 32;
    const FEE_EXECUTED_INDEX: u64 = 164;
    const FEE_EXECUTED_LEN: u64 = 32;
    const EXPIRATION_BLOCK_INDEX: u64 = 196;
    const EXPIRATION_BLOCK_LEN: u64 = 32;
    const HOOK_DATA_INDEX: u64 = 228;

    // Minimum V2 burn message length (without hookData)
    // 4 + 32 + 32 + 32 + 32 + 32 + 32 + 32 = 228 bytes
    const MIN_BURN_MESSAGE_LEN: u64 = 228;

    // Empty values for feeExecuted and expirationBlock during serialization
    const EMPTY_FEE_EXECUTED: u256 = 0;
    const EMPTY_EXPIRATION_BLOCK: u256 = 0;

    // Errors
    const EINVALID_MESSAGE_LENGTH: u64 = 1;

    package fun get_version(message: &vector<u8>): u32 {
        deserialize::deserialize_u32(message, VERSION_INDEX, VERSION_LEN)
    }

    package fun get_burn_token(message: &vector<u8>): address {
        deserialize::deserialize_address(message, BURN_TOKEN_INDEX, BURN_TOKEN_LEN)
    }

    package fun get_mint_recipient(message: &vector<u8>): address {
        deserialize::deserialize_address(message, MINT_RECIPIENT_INDEX, MINT_RECIPIENT_LEN)
    }

    package fun get_amount(message: &vector<u8>): u256 {
        deserialize::deserialize_u256(message, AMOUNT_INDEX, AMOUNT_LEN)
    }

    package fun get_message_sender(message: &vector<u8>): address {
        deserialize::deserialize_address(message, MSG_SENDER_INDEX, MSG_SENDER_LEN)
    }

    package fun get_max_fee(message: &vector<u8>): u256 {
        deserialize::deserialize_u256(message, MAX_FEE_INDEX, MAX_FEE_LEN)
    }

    package fun get_fee_executed(message: &vector<u8>): u256 {
        deserialize::deserialize_u256(message, FEE_EXECUTED_INDEX, FEE_EXECUTED_LEN)
    }

    package fun get_expiration_block(message: &vector<u8>): u256 {
        deserialize::deserialize_u256(message, EXPIRATION_BLOCK_INDEX, EXPIRATION_BLOCK_LEN)
    }

    package fun get_hook_data(message: &vector<u8>): vector<u8> {
        message.slice(HOOK_DATA_INDEX, message.length())
    }

    // Formats a V2 burn message
    // Note: feeExecuted and expirationBlock are set to 0 during serialization
    package fun serialize(
        version: u32,
        burn_token: address,
        mint_recipient: address,
        amount: u256,
        message_sender: address,
        max_fee: u256,
        hook_data: &vector<u8>
    ): vector<u8> {
        let result = vector::empty<u8>();
        result.append(serialize::serialize_u32(version));
        result.append(serialize::serialize_address(burn_token));
        result.append(serialize::serialize_address(mint_recipient));
        result.append(serialize::serialize_u256(amount));
        result.append(serialize::serialize_address(message_sender));
        result.append(serialize::serialize_u256(max_fee));
        result.append(serialize::serialize_u256(EMPTY_FEE_EXECUTED));
        result.append(serialize::serialize_u256(EMPTY_EXPIRATION_BLOCK));
        result.append(*hook_data);
        result
    }

    // Validates V2 burn message format (>= 228 bytes).
    package fun validate_message(message: &vector<u8>) {
        assert!(message.length() >= MIN_BURN_MESSAGE_LEN, error::invalid_argument(EINVALID_MESSAGE_LENGTH));
    }

    // -----------------------------
    // -------- Unit Tests ---------
    // -----------------------------

    // Following test message is based on ->
    // ETH (Source): https://sepolia.etherscan.io/tx/0x770402a67fa4a771fef59199e7aa9513e78debd6f3e5c5f4d0ad303dc9423401
    // Starknet (Destination): 0x6de57edab841cad098aa24b3f20ef81f44bb5d3d41f784c171d7150b9964993
    // Message: https://iris-api-sandbox.circle.com/v2/messages/0?transactionHash=0x770402a67fa4a771fef59199e7aa9513e78debd6f3e5c5f4d0ad303dc9423401
    // Burn Token: 0x0000000000000000000000001c7D4B196Cb0C7B01d743Fbc6116a902379C7238
    // Mint Recipient: 0x064339e25b634e5c54dd9ea1cb0b174462d8e62af2e7731f9c81950981075971
    // Amount: 100
    // Sender: 0x00000000000000000000000075275aff2d01699d922f045b69ed291311209738
    // Max Fee: 1
    // Fee Executed: 1
    // Expiration Block: 2815337
    // Hook Data: 0xdeadbeef (added)
    // Test Message with empty fee executed and expiration block
    #[test_only] const RAW_TEST_MESSAGE: vector<u8> = x"000000010000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238064339e25b634e5c54dd9ea1cb0b174462d8e62af2e7731f9c81950981075971000000000000000000000000000000000000000000000000000000000000006400000000000000000000000075275aff2d01699d922f045b69ed291311209738000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    // Test Message with fee executed and expiration block
    #[test_only] const RAW_TEST_DESTINATION_MESSAGE: vector<u8> = x"000000010000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238064339e25b634e5c54dd9ea1cb0b174462d8e62af2e7731f9c81950981075971000000000000000000000000000000000000000000000000000000000000006400000000000000000000000075275aff2d01699d922f045b69ed2913112097380000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000002af569";
    #[test_only] const RAW_TEST_MESSAGE_WITH_HOOK_DATA: vector<u8> = x"000000010000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238064339e25b634e5c54dd9ea1cb0b174462d8e62af2e7731f9c81950981075971000000000000000000000000000000000000000000000000000000000000006400000000000000000000000075275aff2d01699d922f045b69ed291311209738000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000deadbeef";
    #[test_only] const RAW_TEST_DESTINATION_MESSAGE_WITH_HOOK_DATA: vector<u8> = x"000000010000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238064339e25b634e5c54dd9ea1cb0b174462d8e62af2e7731f9c81950981075971000000000000000000000000000000000000000000000000000000000000006400000000000000000000000075275aff2d01699d922f045b69ed2913112097380000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000002af569deadbeef";

    #[test_only] const VERSION: u32 = 1;
    #[test_only] const BURN_TOKEN: address = @0x0000000000000000000000001c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    #[test_only] const MINT_RECIPIENT: address = @0x064339e25b634e5c54dd9ea1cb0b174462d8e62af2e7731f9c81950981075971;
    #[test_only] const AMOUNT: u256 = 100;
    #[test_only] const MESSAGE_SENDER: address = @0x00000000000000000000000075275aff2d01699d922f045b69ed291311209738;
    #[test_only] const MAX_FEE: u256 = 1;
    #[test_only] const FEE_EXECUTED: u256 = 1;
    #[test_only] const EXPIRATION_BLOCK: u256 = 2815337;
    #[test_only] const HOOK_DATA: vector<u8> = x"deadbeef";

    #[test_only]
    package fun build_message_for_test(
        version: u32,
        burn_token: address,
        mint_recipient: address,
        amount: u256,
        message_sender: address,
        max_fee: u256,
        fee_executed: u256,
        expiration_block: u256,
        hook_data: &vector<u8>
    ): vector<u8> {
        let result = vector::empty<u8>();
        result.append(serialize::serialize_u32(version));
        result.append(serialize::serialize_address(burn_token));
        result.append(serialize::serialize_address(mint_recipient));
        result.append(serialize::serialize_u256(amount));
        result.append(serialize::serialize_address(message_sender));
        result.append(serialize::serialize_u256(max_fee));
        result.append(serialize::serialize_u256(fee_executed));
        result.append(serialize::serialize_u256(expiration_block));
        result.append(*hook_data);
        result
    }

    #[test]
    fun test_burn_message_serialization() {
        let serialized_message = serialize(
            VERSION,
            BURN_TOKEN,
            MINT_RECIPIENT,
            AMOUNT,
            MESSAGE_SENDER,
            MAX_FEE,
            &HOOK_DATA
        );
        assert_eq(serialized_message, RAW_TEST_MESSAGE_WITH_HOOK_DATA);
    }

    #[test]
    fun test_burn_message_serialization_no_hook_data() {
        let empty_hook_data = vector::empty<u8>();
        let serialized_message = serialize(
            VERSION,
            BURN_TOKEN,
            MINT_RECIPIENT,
            AMOUNT,
            MESSAGE_SENDER,
            MAX_FEE,
            &empty_hook_data
        );
        assert_eq(serialized_message, RAW_TEST_MESSAGE);
        assert_eq(serialized_message.length(), MIN_BURN_MESSAGE_LEN);
    }

    // Test extracting all fields from RAW_TEST_MESSAGE (fee_executed=0, expiration_block=0, no hook_data)
    #[test]
    fun test_deserialize_raw_test_message() {
        let message = RAW_TEST_MESSAGE;
        assert_eq(get_version(&message), VERSION);
        assert_eq(get_burn_token(&message), BURN_TOKEN);
        assert_eq(get_mint_recipient(&message), MINT_RECIPIENT);
        assert_eq(get_amount(&message), AMOUNT);
        assert_eq(get_message_sender(&message), MESSAGE_SENDER);
        assert_eq(get_max_fee(&message), MAX_FEE);
        assert_eq(get_fee_executed(&message), 0);
        assert_eq(get_expiration_block(&message), 0);
        assert_eq(get_hook_data(&message), vector[]);
    }

    // Test extracting all fields from RAW_TEST_DESTINATION_MESSAGE (fee_executed=1, expiration_block=2815337, no hook_data)
    #[test]
    fun test_deserialize_raw_test_destination_message() {
        let message = RAW_TEST_DESTINATION_MESSAGE;
        assert_eq(get_version(&message), VERSION);
        assert_eq(get_burn_token(&message), BURN_TOKEN);
        assert_eq(get_mint_recipient(&message), MINT_RECIPIENT);
        assert_eq(get_amount(&message), AMOUNT);
        assert_eq(get_message_sender(&message), MESSAGE_SENDER);
        assert_eq(get_max_fee(&message), MAX_FEE);
        assert_eq(get_fee_executed(&message), FEE_EXECUTED);
        assert_eq(get_expiration_block(&message), EXPIRATION_BLOCK);
        assert_eq(get_hook_data(&message), vector[]);
    }

    // Test extracting all fields from RAW_TEST_MESSAGE_WITH_HOOK_DATA (fee_executed=0, expiration_block=0, hook_data=deadbeef)
    #[test]
    fun test_deserialize_raw_test_message_with_hook_data() {
        let message = RAW_TEST_MESSAGE_WITH_HOOK_DATA;
        assert_eq(get_version(&message), VERSION);
        assert_eq(get_burn_token(&message), BURN_TOKEN);
        assert_eq(get_mint_recipient(&message), MINT_RECIPIENT);
        assert_eq(get_amount(&message), AMOUNT);
        assert_eq(get_message_sender(&message), MESSAGE_SENDER);
        assert_eq(get_max_fee(&message), MAX_FEE);
        assert_eq(get_fee_executed(&message), 0);
        assert_eq(get_expiration_block(&message), 0);
        assert_eq(get_hook_data(&message), HOOK_DATA);
    }

    // Test extracting all fields from RAW_TEST_DESTINATION_MESSAGE_WITH_HOOK_DATA (fee_executed=1, expiration_block=2815337, hook_data=deadbeef)
    #[test]
    fun test_deserialize_raw_test_destination_message_with_hook_data() {
        let message = RAW_TEST_DESTINATION_MESSAGE_WITH_HOOK_DATA;
        assert_eq(get_version(&message), VERSION);
        assert_eq(get_burn_token(&message), BURN_TOKEN);
        assert_eq(get_mint_recipient(&message), MINT_RECIPIENT);
        assert_eq(get_amount(&message), AMOUNT);
        assert_eq(get_message_sender(&message), MESSAGE_SENDER);
        assert_eq(get_max_fee(&message), MAX_FEE);
        assert_eq(get_fee_executed(&message), FEE_EXECUTED);
        assert_eq(get_expiration_block(&message), EXPIRATION_BLOCK);
        assert_eq(get_hook_data(&message), HOOK_DATA);
    }

    // Test validate_message success cases
    #[test]
    fun test_validate_message_success() {
        // All 4 V2 test messages should pass validation
        validate_message(&RAW_TEST_MESSAGE);
        validate_message(&RAW_TEST_DESTINATION_MESSAGE);
        validate_message(&RAW_TEST_MESSAGE_WITH_HOOK_DATA);
        validate_message(&RAW_TEST_DESTINATION_MESSAGE_WITH_HOOK_DATA);
    }

    // Test validate_message with message too short
    #[test]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_validate_message_too_short() {
        let invalid_message = vector[5, 2, 32, 2, 21, 23];
        validate_message(&invalid_message);
    }

    // Test get_hook_data on a message that is too short (without calling validate first)
    // This should panic because the message length is less than HOOK_DATA_INDEX
    #[test]
    #[expected_failure(abort_code = 0x20004, location = 0x1::vector)]
    fun test_get_hook_data_without_validate_panics() {
        let short_message = vector[0, 0, 0, 1]; // Only 4 bytes (version field only)
        // Attempting to get hook_data on a message shorter than HOOK_DATA_INDEX should panic
        get_hook_data(&short_message);
    }
}

