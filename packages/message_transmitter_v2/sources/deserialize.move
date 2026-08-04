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

module message_transmitter_v2::deserialize {
    use aptos_std::from_bcs;

    #[test_only]
    use std::bcs;
    #[test_only]
    use aptos_extensions::test_utils::assert_eq;

    public fun deserialize_u32(data: &vector<u8>, index: u64, size: u64): u32 {
        let result = data.slice(index, index+size);
        result.reverse();
        from_bcs::to_u32(result)
    }

    public fun deserialize_u64(data: &vector<u8>, index: u64, size: u64): u64 {
        let result = data.slice(index, index+size);
        result.reverse();
        from_bcs::to_u64(result)
    }

    public fun deserialize_u256(data: &vector<u8>, index: u64, size: u64): u256 {
        let result = data.slice(index, index+size);
        result.reverse();
        from_bcs::to_u256(result)
    }

    public fun deserialize_address(data: &vector<u8>, index: u64, size: u64): address {
        let result = data.slice(index, index+size);
        from_bcs::to_address(result)
    }

    #[test]
    public fun test_deserialize_u32() {
        let num: u32 = 1234;
        let serialized = bcs::to_bytes(&num);
        serialized.reverse();

        let deserialized = deserialize_u32(&serialized, 0, serialized.length());
        assert_eq(deserialized, num);
    }

    #[test]
    public fun test_deserialize_u64() {
        let num: u64 = 123456789;
        let serialized = bcs::to_bytes(&num);
        serialized.reverse();

        let deserialized = deserialize_u64(&serialized, 0, serialized.length());
        assert_eq(deserialized, num);
    }

    #[test]
    public fun test_deserialize_u256() {
        let num: u256 = 123456789123456789123456789;
        let serialized = bcs::to_bytes(&num);
        serialized.reverse();

        let deserialized = deserialize_u256(&serialized, 0, serialized.length());
        assert_eq(deserialized, num);
    }

    #[test]
    public fun test_deserialize_address() {
        let address: address = @0xa9fb1b3009dcb79e2fe346c16a604b8fa8ae0a79;
        let serialized = bcs::to_bytes(&address);

        let deserialized = deserialize_address(&serialized, 0, serialized.length());
        assert_eq(deserialized, address);
    }
}
