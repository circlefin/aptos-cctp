# aptos-cctp-private

Official repository for Aptos smart contracts used by the Cross-Chain Transfer Protocol.

---

## Getting Started

### Prerequisites

Before you can start working with the contracts in this repository, make sure you have the following prerequisites installed:

1. Run `make setup` to install required dependencies (Aptos CLI, Import Git submodules).
2. [IntelliJ](https://www.jetbrains.com/idea/download/?section=mac) is recommended for developing Move contracts. Install the [Move Intellij IDE Plugin](https://pontem.network/move-intellij-ide-plugin).

---

## Testing

### Run Aptos and EVM Local Network

```sh
./docker-start-containers.sh
```

### Run Unit Tests for All Package Modules

```sh
make test
```

### Running E2E Tests

```sh
# Install Dependencies
yarn install
```

```sh
# Run e2e tests
yarn test:e2e
```

### Running Example Scripts on Testnet
1. Rename .env.example to .env and fill in the required environment variables.
2. Run the example script for Base/EVM -> Aptos
```sh
yarn receive-message-example
```
3. Run the example script for Aptos -> Base/EVM
```sh
yarn deposit-for-burn-example
```


## Deployment

1. Create a deployer keypair and fund it with APT
2. Deploy MessageTransmitter and TokenMessengerMinter package

```sh
yarn deploy --privateKey=<key> --rpc=<rpcUrl>  --aptosExtensionsPackageId=<packageId> --stablecoinPackageId=<packageId>
```

3. Verify source bytecode

```sh
# Message Transmitter
yarn verify-pkg --packageName=message_transmitter --rpc=<rpcUrl> --packageId=<MessageTransmitterPackageId> --namedDeps aptos_extensions=<packageId>,deployer=<deployerAccountAddress>

# TokenMessengerMinter
yarn verify-pkg --packageName=token_messenger_minter --rpc=<rpcUrl> --packageId=<TokenMessengerMinterPackageId> --namedDeps aptos_extensions=<packageId>,deployer=<deployerAccountAddress>,message_transmitter=<packageId>,stablecoin=<packageId>
```

## Upgrading

1. Build payload for publishing

```sh
# Message Transmitter
aptos move build-publish-payload --package-dir packages/message_transmitter --named-addresses deployer=<deployerAccountAddress>,aptos_extensions=<packageId>,message_transmitter=<packageId> --json-output-file upgrade.json

# Token Messenger Minter
aptos move build-publish-payload --package-dir packages/token_messenger_minter --named-addresses deployer=<deployerAccountAddress>,aptos_extensions=<packageId>,message_transmitter=<packageId>,stablecoin=<packageId>,token_messenger_minter=<packageId> --json-output-file upgrade.json
```

2. Execute Tx for upgrading

```sh
yarn upgrade-pkg --privateKey=<upgradeAdminKey> --rpc=<rpcUrl> --payloadFilePath=upgrade.json --aptosExtensionsPackageId=<packageId> --packageId=<packageId>
```
