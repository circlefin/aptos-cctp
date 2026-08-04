# V2 Precompiled Move Scripts (Testnet)

Precompiled `.mv` bytecode files for the V2 Aptos Move scripts, compiled against testnet named addresses.

## Files

- `deposit_for_burn.mv` — Burns USDC on Aptos, sends cross-chain message to EVM
- `deposit_for_burn_with_hook.mv` — Same as above, with hook data for destination-chain execution
- `receive_message.mv` — Receives cross-chain message from EVM, mints USDC on Aptos

## Recompiling

If the V2 packages are redeployed on testnet, recompile and replace these files.

### Prerequisites
- Aptos CLI installed
- Deployed package addresses for all V2 dependencies (see chain-expansion-scripts sandbox config)

### Steps

1. Compile with `--named-addresses` pointing to the deployed testnet addresses:
   ```bash
   aptos move compile \
     --package-dir packages/stablecoin_handler \
     --named-addresses \
       stablecoin_handler=<ADDRESS>,\
       token_messenger_minter_v2=<ADDRESS>,\
       message_transmitter_v2=<ADDRESS>,\
       aptos_extensions=<ADDRESS>,\
       cctp_extensions=<ADDRESS>,\
       deployer=<ADDRESS>,\
       stablecoin=<ADDRESS>
   ```

2. Copy the compiled scripts:
   ```bash
   cp packages/stablecoin_handler/build/StablecoinHandler/bytecode_scripts/deposit_for_burn.mv typescript/example/precompiled-move-scripts/testnet/v2/
   cp packages/stablecoin_handler/build/StablecoinHandler/bytecode_scripts/deposit_for_burn_with_hook.mv typescript/example/precompiled-move-scripts/testnet/v2/
   cp packages/stablecoin_handler/build/StablecoinHandler/bytecode_scripts/receive_message.mv typescript/example/precompiled-move-scripts/testnet/v2/
   ```

## Source Files

The Move script source code lives at:
- `packages/stablecoin_handler/scripts/deposit_for_burn.move`
- `packages/stablecoin_handler/scripts/deposit_for_burn_with_hook.move`
- `packages/stablecoin_handler/scripts/receive_message.move`
