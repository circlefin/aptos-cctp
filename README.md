# aptos-cctp

Official repository for Aptos smart contracts used by the [Cross-Chain Transfer Protocol](https://developers.circle.com/stablecoins/cctp-getting-started).

This repository contains both **CCTP V1** and **CCTP V2** implementations.

## Packages

### V1

| Package                 | Description                                              |
| :---------------------- | :------------------------------------------------------- |
| `message_transmitter`   | Generic message passing (send / receive messages).      |
| `token_messenger_minter`| Burns and mints tokens for cross-chain transfers.       |

### V2

CCTP V2 introduces a multi-token handler architecture, fees, denylisting, and a hot potato receipt flow. It is split into four packages:

| Package                    | Description                                                                                          |
| :------------------------- | :--------------------------------------------------------------------------------------------------- |
| `message_transmitter_v2`   | Generic V2 message passing with `destination_caller` and `min_finality_threshold` support.          |
| `token_messenger_minter_v2`| Token-agnostic burn/mint orchestration with fee control, denylisting, and a handler registry.       |
| `stablecoin_handler`       | Token-specific mint/burn logic for stablecoins (USDC, EURC, ...). Hosts the V2 Move scripts.         |
| `cctp_extensions`          | Shared V2 extensions (e.g. `rescuable`).                                                             |

---

## Getting Started

### Prerequisites

Before you can start working with the contracts in this repository, make sure you have the following prerequisites installed:

1. Run `make setup` to install required dependencies (Aptos CLI, import Git submodules).
2. [IntelliJ](https://www.jetbrains.com/idea/download/?section=mac) is recommended for developing Move contracts. Install the [Move Intellij IDE Plugin](https://pontem.network/move-intellij-ide-plugin).

> **V2 note:** V2 packages require the `stablecoin-aptos` submodule to resolve `AptosFramework` to the same revision the V2 packages pin. Until `circlefin/stablecoin-aptos` publishes a V2-compatible release, run `make setup-v2` instead of `make setup` for V2 work. It runs `make setup` and then applies [`patches/stablecoin-aptos-v2.patch`](patches/stablecoin-aptos-v2.patch) to the submodule. `./docker-start-containers.sh v2` does this automatically.

---

## Testing

### Run Aptos and EVM Local Network

```sh
# V1 (starts Aptos localnet + EVM contracts)
./docker-start-containers.sh

# V2 (starts Aptos localnet only)
./docker-start-containers.sh v2
```

### Run Unit Tests

```sh
# All packages (V1 + V2)
make test

# V1 packages only
make test-v1

# V2 packages only
make test-v2
```

### Running E2E Tests

```sh
# Install dependencies
yarn install
```

```sh
# V1 e2e tests
yarn test:e2e

# V2 e2e tests
yarn test:e2e-v2
```

### Running Example Scripts on Testnet

1. Rename `.env.example` to `.env` and fill in the required environment variables.

#### V1

```sh
# Base/EVM -> Aptos
yarn receive-message-example

# Aptos -> Base/EVM
yarn deposit-for-burn-example
```

#### V2

```sh
# Base/EVM -> Aptos
yarn receive-message-v2-example

# Base/EVM -> Aptos (fast transfer)
yarn receive-message-v2-fast-example

# Aptos -> Base/EVM
yarn deposit-for-burn-v2-example

# Aptos -> Base/EVM with hook data
yarn deposit-for-burn-with-hook-v2-example
```

See [typescript/example/v2/README.md](typescript/example/v2/README.md) for more details on the V2 examples.

---

## Deployment

### V1

1. Create a deployer keypair and fund it with APT.
2. Deploy the `MessageTransmitter` and `TokenMessengerMinter` packages.

```sh
yarn deploy --privateKey=<key> --rpc=<rpcUrl>  --aptosExtensionsPackageId=<packageId> --stablecoinPackageId=<packageId>
```

3. Verify source bytecode.

```sh
# Message Transmitter
yarn verify-pkg --packageName=message_transmitter --rpc=<rpcUrl> --packageId=<MessageTransmitterPackageId> --namedDeps aptos_extensions=<packageId>,deployer=<deployerAccountAddress>

# TokenMessengerMinter
yarn verify-pkg --packageName=token_messenger_minter --rpc=<rpcUrl> --packageId=<TokenMessengerMinterPackageId> --namedDeps aptos_extensions=<packageId>,deployer=<deployerAccountAddress>,message_transmitter=<packageId>,stablecoin=<packageId>
```

### V2

1. Create a deployer keypair and fund it with APT.
2. Calculate the deployment addresses for the V2 packages.

```sh
yarn calculate-deployment-addresses-v2 --deployer=<deployerAddress>
```

3. Deploy the `MessageTransmitterV2`, `TokenMessengerMinterV2`, `CctpExtensions`, and `StablecoinHandler` packages.

```sh
yarn deploy-v2 --privateKey=<key> --rpc=<rpcUrl> --aptosExtensionsPackageId=<packageId> --stablecoinPackageId=<packageId>
```

4. Verify source bytecode for all V2 packages.

```sh
yarn verify-all-v2-pkgs \
  --deployer=<deployerAddress> \
  --rpc=<rpcUrl> \
  --aptosExtensionsPackageId=<packageId> \
  --stablecoinPackageId=<packageId> \
  --cctpExtensionsPackageId=<packageId> \
  --messageTransmitterV2PackageId=<packageId> \
  --tokenMessengerMinterV2PackageId=<packageId> \
  --stablecoinHandlerPackageId=<packageId>
```

---

## Upgrading

1. Build payload for publishing.

```sh
# Message Transmitter
aptos move build-publish-payload --package-dir packages/message_transmitter --named-addresses deployer=<deployerAccountAddress>,aptos_extensions=<packageId>,message_transmitter=<packageId> --json-output-file upgrade.json

# Token Messenger Minter
aptos move build-publish-payload --package-dir packages/token_messenger_minter --named-addresses deployer=<deployerAccountAddress>,aptos_extensions=<packageId>,message_transmitter=<packageId>,stablecoin=<packageId>,token_messenger_minter=<packageId> --json-output-file upgrade.json
```

2. Execute the transaction for upgrading.

```sh
yarn upgrade-pkg --privateKey=<upgradeAdminKey> --rpc=<rpcUrl> --payloadFilePath=upgrade.json --aptosExtensionsPackageId=<packageId> --packageId=<packageId>
```

---

## License

This project is licensed under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) license.
