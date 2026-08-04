// Copyright (c) 2026, Circle Internet Group, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Script for burning stablecoin tokens for cross-chain transfer with hook data.
// This is the V2 multi-token architecture script for stablecoin (USDC, EURC, etc.)
script {
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use token_messenger_minter_v2::token_messenger_minter;
    use stablecoin_handler::handler;
    use aptos_framework::error;

    const EINVALID_HOOK_DATA: u64 = 1;

    /// Burn stablecoin for cross-chain transfer.
    /// This orchestrates the full outbound flow:
    /// 1. Withdraw asset from caller's primary fungible store
    /// 2. TokenMessengerMinter: Validate parameters, create BurnReceipt
    /// 3. StablecoinHandler: Burn tokens, complete flow (send message, emit event)
    ///
    /// If destination_caller is non-zero, the mint on the destination chain
    /// must be called by that address.
    /// 
    /// This script will panic if the hook data is empty.
    fun deposit_for_burn_with_hook(
        caller: &signer,
        amount: u64,
        destination_domain: u32,
        mint_recipient: address,
        destination_caller: address,
        burn_token: address,
        max_fee: u64,
        min_finality_threshold: u32,
        hook_data: vector<u8>,
    ) {
        // Verify hook data is not empty
        assert!(hook_data.length() > 0, error::invalid_argument(EINVALID_HOOK_DATA));

        // 1. Withdraw asset from caller
        let token_obj: Object<Metadata> = object::address_to_object(burn_token);
        let asset = primary_fungible_store::withdraw(caller, token_obj, amount);

        // 2. TokenMessengerMinter: Validate and create BurnReceipt
        let (burn_receipt, asset) = token_messenger_minter::deposit_for_burn(
            caller,
            asset,
            destination_domain,
            mint_recipient,
            destination_caller,
            max_fee,
            min_finality_threshold,
            hook_data,
        );

        // 3. StablecoinHandler: Burn tokens, complete flow
        handler::burn(burn_receipt, asset);

        // BurnReceipt consumed - transaction complete
    }
}


