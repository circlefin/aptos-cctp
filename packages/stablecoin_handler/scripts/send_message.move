// Copyright (c) 2026, Circle Internet Group, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Script for sending a general message via MessageTransmitter V2.
script {
    use message_transmitter_v2::message_transmitter;

    /// Send a general cross-chain message.
    fun send_message(
        caller: &signer,
        destination_domain: u32,
        recipient: address,
        destination_caller: address,
        min_finality_threshold: u32,
        message_body: vector<u8>
    ) {
        message_transmitter::send_message(
            caller,
            destination_domain,
            recipient,
            destination_caller,
            min_finality_threshold,
            &message_body
        );
    }
}
