# V2 Example Scripts

Example scripts demonstrating cross-chain USDC transfers using CCTP V2 between Aptos and EVM chains.

## Scripts

| Script | Direction | Description |
|--------|-----------|-------------|
| `depositForBurnV2.ts` | Aptos → EVM | Burn USDC on Aptos, mint on EVM (finalized) |
| `depositForBurnWithHookV2.ts` | Aptos → EVM | Same as above, with hook data for destination-chain execution |
| `receiveMessageV2.ts` | EVM → Aptos | Burn USDC on EVM, mint on Aptos (finalized) |
| `receiveMessageV2Fast.ts` | EVM → Aptos | Same as above, with lower finality threshold and fee |

## Environment Variables

Create a `typescript/.env` file with the following:

```bash
# Keys
APTOS_PRIVATE_KEY=               # Aptos account private key (hex)
EVM_PRIVATE_KEY=                 # EVM account private key (hex)

# EVM
EVM_RPC_URL=                     # EVM RPC endpoint (e.g. Base Sepolia)

# V2 Contract Addresses (Aptos)
APTOS_BURN_TOKEN=                # Stablecoin object address on Aptos

# V2 Contract Addresses (EVM)
EVM_MESSAGE_TRANSMITTER_V2_ADDRESS=   # MessageTransmitterV2 proxy
EVM_TOKEN_MESSENGER_V2_ADDRESS=       # TokenMessengerV2 proxy
EVM_USDC_ADDRESS=                     # USDC contract on EVM chain

# Optional
EVM_DESTINATION_DOMAIN=          # EVM chain domain ID (default: 6, Base Sepolia)
EVM_SOURCE_DOMAIN=               # EVM chain domain ID when EVM is source (default: 6)
IRIS_API_URL=                    # Iris API (default: https://iris-api-sandbox.circle.com)
```

## Usage

```bash
yarn deposit-for-burn-v2-example
yarn deposit-for-burn-with-hook-v2-example
yarn receive-message-v2-example
yarn receive-message-v2-fast-example
```

## Prerequisites

- Aptos account funded with USDC and APT (gas)
- EVM account funded with USDC and ETH (gas)
- V2 contracts deployed on both chains
