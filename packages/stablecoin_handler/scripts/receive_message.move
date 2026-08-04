// Copyright (c) 2025, Circle Internet Group, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Script for receiving cross-chain messages and minting stablecoin tokens.
// This is the V2 multi-token architecture script for stablecoin (USDC, EURC, etc.)
script {
    use message_transmitter_v2::message_transmitter;
    use token_messenger_minter_v2::token_messenger_minter;
    use stablecoin_handler::handler;

    /// Receive cross-chain message and mint stablecoin
    /// This orchestrates the full inbound flow:
    /// 1. MessageTransmitter: Verify attestation, create Receipt
    /// 2. TokenMessengerMinter: Validate message, create MintReceipt
    /// 3. StablecoinHandler: Mint tokens, complete flow
    fun receive_message(
        caller: &signer,
        message: vector<u8>,
        attestation: vector<u8>
    ) {
        // 1. MessageTransmitter: Verify attestation, create Receipt
        let receipt = message_transmitter::receive_message(caller, &message, &attestation);

        // 2. TokenMessengerMinter: Validate message, create MintReceipt
        let mint_receipt = token_messenger_minter::prepare_mint(receipt);

        // 3. StablecoinHandler: Mint tokens, complete flow
        handler::mint(mint_receipt);

        // All hot potatoes consumed - transaction complete
    }
}


