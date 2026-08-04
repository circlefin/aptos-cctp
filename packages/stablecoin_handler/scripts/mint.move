// Copyright (c) 2026, Circle Internet Group, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Script for minting stablecoin tokens to a recipient.
// This is used for testing purposes to fund accounts with USDC.
script {
    use aptos_framework::primary_fungible_store;
    use stablecoin::treasury;

    /// Mint stablecoin tokens to a recipient.
    /// The caller must be a configured minter with sufficient allowance.
    fun mint(caller: &signer, amount: u64, mint_recipient: address) {
        let fa = treasury::mint(caller, amount);
        primary_fungible_store::deposit(mint_recipient, fa);
    }
}
