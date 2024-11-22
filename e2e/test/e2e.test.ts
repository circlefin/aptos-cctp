/*
 * Copyright (c) 2024, Circle Internet Group, Inc.
 * All rights reserved.
 *
 * Circle Internet Group, Inc. CONFIDENTIAL
 *
 * This file includes unpublished proprietary source code of Circle Internet
 * Group, Inc. The copyright notice above does not evidence any actual or
 * intended publication of such source code. Disclosure of this source code
 * or any related proprietary information is strictly prohibited without
 * the express written permission of Circle Internet Group, Inc.
 */

import { MessageTransmitterClient } from "../../typescript/aptos/client/messageTransmitterClient";
import {
  Account,
  AccountAddress,
  Aptos,
  Ed25519Account,
  MoveVector,
  U32,
  U64,
  U8,
  UserTransactionResponse,
} from "@aptos-labs/ts-sdk";
import { AptosExtensionsClient } from "../../typescript/aptos/client/aptosExtensionsClient";
import {
  attestToMessage,
  EvmContractDefinition,
  generateEvmBurn,
  receiveEvm,
} from "../../typescript/evm/client/evmContractClient";
import { Web3 } from "web3";
import fs from "fs";
import { afterAll, beforeAll, describe, expect, jest, test } from "@jest/globals";
import dotenv from "dotenv";
import { TokenMessengerMinterClient } from "../../typescript/aptos/client/tokenMessengerMinterClient";
import { MoveModule } from "../../typescript/aptos/utils/moveModule";
import {
  generateFundedAccount,
  generateFundedAccountFromPrivateKey,
  getAptosClient,
  getEventByType,
  normalizeAddress,
} from "../../typescript/aptos/utils/helper";
import { StablecoinClient } from "../../typescript/aptos/client/stablecoinClient";
import waitForExpect from "wait-for-expect";

jest.setTimeout(200_000);
dotenv.config();

describe("End to End Tests", () => {
  const cctpPackagesFilePath = "packages";
  const stablecoinFilePath = "stablecoin-aptos/packages";

  let deployer: Ed25519Account;
  let messageTransmitterClient: MessageTransmitterClient;
  let tokenMessengerMinterClient: TokenMessengerMinterClient;
  let aptosExtensionsClient: AptosExtensionsClient;
  let stablecoinClient: StablecoinClient;
  let web3: Web3;
  let contractDefinition: EvmContractDefinition;
  let aptos: Aptos;
  let secondaryMinterController: Ed25519Account;
  let secondaryMinter: Ed25519Account;

  const evmUserAddress = "0xfabb0ac9d68b0b445fb7357272ff202c5651694a";
  const usdcContractAddress = `${process.env.EVM_USDC_ADDRESS}`;

  const setupStablecoinAndAptosExtensions = async (): Promise<{
    aptosExtensionsPackageId: string;
    stablecoinPackageId: string;
  }> => {
    const aptosExtensionsPackageId = await aptosExtensionsClient.publishPackage(stablecoinFilePath);
    const stablecoinPackageId = await stablecoinClient.publishPackage(stablecoinFilePath, aptosExtensionsPackageId);
    await stablecoinClient.initializeState(
      "USDC",
      "USDC",
      new U8(6),
      "https://www.circle.com/hubfs/Brand/USDC/USDC_icon_32x32.png",
      "https://circle.com/usdc"
    );
    return { stablecoinPackageId, aptosExtensionsPackageId };
  };

  const setupAptos = async () => {
    aptos = getAptosClient();
    deployer = await generateFundedAccount(aptos);
    messageTransmitterClient = new MessageTransmitterClient(aptos, deployer);
    tokenMessengerMinterClient = new TokenMessengerMinterClient(aptos, deployer);
    aptosExtensionsClient = new AptosExtensionsClient(aptos, deployer);
    stablecoinClient = new StablecoinClient(aptos, deployer);
    const { aptosExtensionsPackageId, stablecoinPackageId } = await setupStablecoinAndAptosExtensions();

    const messageTransmitterPackageId = await messageTransmitterClient.publishPackage(
      "packages",
      aptosExtensionsPackageId,
      "sparse"
    );
    console.log(`MessageTransmitter package ID: ${messageTransmitterPackageId}\n`);

    const tokenMessengerMinterPackageId = await tokenMessengerMinterClient.publishPackage(
      "packages",
      aptosExtensionsPackageId,
      messageTransmitterPackageId,
      stablecoinPackageId,
      "sparse"
    );
    console.log(`TokenMessengerMinter package ID: ${tokenMessengerMinterPackageId}\n`);

    // Initialize Message Transmitter
    const localDomain = new U32(9);
    const attester = AccountAddress.from(`${process.env.EVM_ATTESTER_ADDRESS}`);
    const maxMessageBodySize = new U64(8192);
    const version = new U32(0);
    await messageTransmitterClient.initializeState(localDomain, attester, maxMessageBodySize, version);
    console.log(`Message Transmitter initialized.\n`);

    // Initialize Token Messenger Minter
    const messageBodyVersion = new U32(0);
    await tokenMessengerMinterClient.initializeState(messageBodyVersion, deployer.accountAddress);
    console.log(`Token Messenger Minter initialized.\n`);

    messageTransmitterClient.packageId = messageTransmitterPackageId;
    tokenMessengerMinterClient.packageId = tokenMessengerMinterPackageId;

    // Configure minter
    await stablecoinClient.configureController(deployer.accountAddress, tokenMessengerMinterClient.signerAddress());
    await stablecoinClient.configureMinter(deployer, new U64(100_000_000));

    secondaryMinterController = await generateFundedAccount(aptos);
    secondaryMinter = await generateFundedAccount(aptos);
    await stablecoinClient.configureController(
      secondaryMinterController.accountAddress,
      secondaryMinter.accountAddress
    );
    await stablecoinClient.configureMinter(secondaryMinterController, new U64(100_000_000));

    // Add ETH remote token messenger in Aptos
    await tokenMessengerMinterClient.addRemoteTokenMessenger(
      new U32(0),
      AccountAddress.from(`${process.env.EVM_TOKEN_MESSENGER_ADDRESS}`)
    );

    // Add remote token messenger in evm
    const tokenMessengerContractOwner = web3.eth.accounts.privateKeyToAccount(
      `${process.env.EVM_TOKEN_MESSENGER_DEPLOYER_KEY}`
    );
    await contractDefinition.tokenMessengerContract.methods
      .addRemoteTokenMessenger(9, normalizeAddress(tokenMessengerMinterClient.getObjectAddress().toString()))
      .send({ from: tokenMessengerContractOwner.address });

    // Link Token Pair in EVM
    const tokenControllerAccount = web3.eth.accounts.privateKeyToAccount(
      `${process.env.EVM_TOKEN_CONTROLLER_DEPLOYER_KEY}`
    );

    await contractDefinition.tokenMinterContract.methods
      .linkTokenPair(usdcContractAddress, 9, normalizeAddress(stablecoinClient.getObjectAddress().toString()))
      .send({ from: tokenControllerAccount.address });

    // Link Token Pair in APtos
    await tokenMessengerMinterClient.linkTokenPair(
      stablecoinClient.getObjectAddress(),
      new U32(0),
      AccountAddress.from(usdcContractAddress)
    );

    // Set max burn amount per message
    await tokenMessengerMinterClient.setMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress(), new U64(1));
  };

  const setupEvm = async () => {
    web3 = new Web3(new Web3.providers.HttpProvider(`${process.env.EVM_RPC_URL}`));
    const evmUSDCAddress = `${process.env.EVM_USDC_ADDRESS}`;
    const evmMessageTransmitterAddress = `${process.env.EVM_MESSAGE_TRANSMITTER_ADDRESS}`;
    const evmTokenMessengerAddress = `${process.env.EVM_TOKEN_MESSENGER_ADDRESS}`;
    const evmTokenMinterContractAddress = `${process.env.EVM_TOKEN_MINTER_ADDRESS}`;

    const messageTransmitterInterface = JSON.parse(
      fs.readFileSync("evm-cctp-contracts/cctp-interfaces/MessageTransmitter.sol/MessageTransmitter.json").toString()
    );
    const usdcInterface = JSON.parse(
      fs.readFileSync("evm-cctp-contracts/usdc-interfaces/FiatTokenV2_1.sol/FiatTokenV2_1.json").toString()
    );
    const tokenMessengerInterface = JSON.parse(
      fs.readFileSync("evm-cctp-contracts/cctp-interfaces/TokenMessenger.sol/TokenMessenger.json").toString()
    );
    const tokenMinterContractInterface = JSON.parse(
      fs.readFileSync("evm-cctp-contracts/cctp-interfaces/TokenMinter.sol/TokenMinter.json").toString()
    );

    const messageTransmitterContract = new web3.eth.Contract(
      messageTransmitterInterface.abi,
      evmMessageTransmitterAddress
    );
    const tokenMessengerContract = new web3.eth.Contract(tokenMessengerInterface.abi, evmTokenMessengerAddress);
    const usdcContract = new web3.eth.Contract(usdcInterface.abi, evmUSDCAddress);
    const tokenMinterContract = new web3.eth.Contract(tokenMinterContractInterface.abi, evmTokenMinterContractAddress);

    contractDefinition = {
      web3,
      messageTransmitterContract,
      messageTransmitterContractAddress: evmMessageTransmitterAddress,
      tokenMessengerContract,
      tokenMessengerContractAddress: evmTokenMessengerAddress,
      tokenMinterContract,
      tokenMinterContractAddress: evmTokenMinterContractAddress,
      usdcContract,
      usdcContractAddress: evmUSDCAddress,
    } as EvmContractDefinition;
  };

  beforeAll(async () => {
    await setupEvm();
    await setupAptos();
  });

  afterAll(async () => {
    // Remove remote token messenger in evm
    try {
      const tokenMessengerContractInterface = JSON.parse(
        fs.readFileSync("evm-cctp-contracts/cctp-interfaces/TokenMessenger.sol/TokenMessenger.json").toString()
      );
      const evmTokenMessengerContractAddress = `${process.env.EVM_TOKEN_MESSENGER_ADDRESS}`;
      const tokenMessengerContract = new web3.eth.Contract(
        tokenMessengerContractInterface.abi,
        evmTokenMessengerContractAddress
      );
      const tokenMessengerContractOwner = web3.eth.accounts.privateKeyToAccount(
        `${process.env.EVM_TOKEN_MESSENGER_DEPLOYER_KEY}`
      );
      tokenMessengerContract.methods.removeRemoteTokenMessenger(9).send({ from: tokenMessengerContractOwner.address });

      // Unlink Token Pair
      const tokenMinterContractInterface = JSON.parse(
        fs.readFileSync("evm-cctp-contracts/cctp-interfaces/TokenMinter.sol/TokenMinter.json").toString()
      );
      const evmTokenMinterContractAddress = `${process.env.EVM_TOKEN_MINTER_ADDRESS}`;
      const tokenMinterContract = new web3.eth.Contract(
        tokenMinterContractInterface.abi,
        evmTokenMinterContractAddress
      );
      const tokenControllerAccount = web3.eth.accounts.privateKeyToAccount(
        `${process.env.EVM_TOKEN_CONTROLLER_DEPLOYER_KEY}`
      );

      const usdcContractAddress = `${process.env.EVM_USDC_ADDRESS}`;
      tokenMinterContract.methods
        .unlinkTokenPair(usdcContractAddress, 9, normalizeAddress(stablecoinClient.getObjectAddress().toString()))
        .send({ from: tokenControllerAccount.address });
    } catch (e) {
      console.error(e);
    }
  });

  describe("Admin Functions", () => {
    describe("MessageTransmitter Client", () => {
      test("Enable & Disable Attester", async () => {
        // Enable attester
        const newAttester = Account.generate().accountAddress;
        await messageTransmitterClient.enableAttester(newAttester);
        expect(await messageTransmitterClient.isEnabledAttester(newAttester)).toBeTruthy();

        // Verify random address is not enabled
        expect(
          await messageTransmitterClient.isEnabledAttester(messageTransmitterClient.getObjectAddress())
        ).toBeFalsy();

        // Disable attester
        await messageTransmitterClient.disableAttester(newAttester);
        expect(await messageTransmitterClient.isEnabledAttester(newAttester)).toBeFalsy();
      });
      test("Get & Update Attester Manager", async () => {
        // Get original attester manager
        const originalAttesterManager = await messageTransmitterClient.getAttesterManager();
        expect(originalAttesterManager.toString()).toBe(deployer.accountAddress.toString());

        // Update attester manager
        const newAttesterManager = Account.generate().accountAddress;
        await messageTransmitterClient.updateAttesterManager(newAttesterManager);
        expect((await messageTransmitterClient.getAttesterManager()).toString()).toBe(newAttesterManager.toString());

        // Revert to original attester manager
        await messageTransmitterClient.updateAttesterManager(originalAttesterManager);
        expect((await messageTransmitterClient.getAttesterManager()).toString()).toBe(
          originalAttesterManager.toString()
        );
      });
      test("Fetch States", async () => {
        // Get & Verify local_domain
        expect(await messageTransmitterClient.getLocalDomain()).toEqual(9);

        // Get & Verify version
        expect(await messageTransmitterClient.getVersion()).toEqual(0);

        // Get & Verify max_message_body_size
        expect(await messageTransmitterClient.getMaxMessageBodySize()).toEqual("8192");

        // Get & Verify signature_threshold
        expect(await messageTransmitterClient.getSignatureThreshold()).toEqual("1");

        // Get & Verify enabled_attesters
        expect(await messageTransmitterClient.getNumEnabledAttesters()).toEqual("1");
      });
    });
    describe("TokenMessengerMinter Client", () => {
      test("Add & Remove Remote Token Messenger", async () => {
        // Add remote token messenger
        const remoteDomain = new U32(1);
        const remoteTokenMessenger = Account.generate().accountAddress;
        await tokenMessengerMinterClient.addRemoteTokenMessenger(remoteDomain, remoteTokenMessenger);

        // Verify remote token messenger was added
        const remoteTokenMessengerAddress = await tokenMessengerMinterClient.getRemoteTokenMessenger(remoteDomain);
        expect(remoteTokenMessengerAddress).toStrictEqual(remoteTokenMessenger);

        // Remove remote token messenger
        await tokenMessengerMinterClient.removeRemoteTokenMessenger(remoteDomain);
        await expect(() => tokenMessengerMinterClient.getRemoteTokenMessenger(remoteDomain)).rejects.toThrow();
      });
      test("Fetch states", async () => {
        // Get & Verify message_body_version
        expect(await tokenMessengerMinterClient.getMessageBodyVersion()).toEqual(0);

        // Get & Verify num_remote_token_messengers
        expect(await tokenMessengerMinterClient.getNumRemoteTokenMessenger()).toEqual("1");

        // Get & Verify get_linked_token
        expect(
          await tokenMessengerMinterClient.getLinkedToken(new U32(0), AccountAddress.from(usdcContractAddress))
        ).toEqual(stablecoinClient.getObjectAddress());
      });
    });
    describe("AptosExtensions Client", () => {
      test("Change & Fetch pauser, isPaused", async () => {
        const newPauser = Account.generate().accountAddress;
        await aptosExtensionsClient.updatePauser(deployer, messageTransmitterClient.getObjectAddress(), newPauser);

        const pauser = await aptosExtensionsClient.pauser(messageTransmitterClient.getObjectAddress());
        expect(pauser.equals(newPauser)).toBe(true);

        const isPaused = await aptosExtensionsClient.isPaused(messageTransmitterClient.getObjectAddress());
        expect(isPaused).toBeFalsy();
      });

      test("Transfer, Accept & Fetch ownership", async () => {
        // Initiate owner transfer
        const newOwner = await generateFundedAccount(aptos);
        await aptosExtensionsClient.transferOwnership(
          deployer,
          messageTransmitterClient.getObjectAddress(),
          newOwner.accountAddress
        );

        // Fetch Pending owner
        const pendingOwner = (await aptosExtensionsClient.pendingOwner(
          messageTransmitterClient.getObjectAddress()
        )) as AccountAddress;
        expect(pendingOwner.equals(newOwner.accountAddress)).toBe(true);

        // Accept Ownership
        await aptosExtensionsClient.acceptOwnership(newOwner, messageTransmitterClient.getObjectAddress());

        // Fetch current owner
        const owner = await aptosExtensionsClient.owner(messageTransmitterClient.getObjectAddress());
        expect(owner.equals(newOwner.accountAddress)).toBe(true);
      });

      test("Change, Accept & Fetch Admin", async () => {
        // Initiate admin change
        const newAdmin = await generateFundedAccount(aptos);
        await aptosExtensionsClient.changeAdmin(deployer, messageTransmitterClient.packageId, newAdmin.accountAddress);

        // Fetch Pending admin
        const pendingAdmin = (await aptosExtensionsClient.pendingAdmin(
          messageTransmitterClient.packageId
        )) as AccountAddress;
        expect(pendingAdmin.equals(newAdmin.accountAddress)).toBe(true);

        // Accept Ownership
        await aptosExtensionsClient.acceptAdmin(newAdmin, messageTransmitterClient.packageId);

        // Fetch current owner
        const admin = await aptosExtensionsClient.admin(messageTransmitterClient.packageId);
        expect(admin.equals(newAdmin.accountAddress)).toBe(true);
      });
    });
  });

  describe("E2E Tests", () => {
    test("EVM <-> APTOS", async () => {
      const aptosUser = await generateFundedAccount(aptos);

      // Send 1 USDC from EVM to APTOS
      const depositForBurnTx = await generateEvmBurn(
        contractDefinition,
        evmUserAddress,
        aptosUser.accountAddress.toString(),
        9
      );
      const receiveTx = await tokenMessengerMinterClient.handleReceiveMessage(
        cctpPackagesFilePath,
        MoveVector.U8(depositForBurnTx.messageBytes),
        MoveVector.U8(depositForBurnTx.attestation)
      );

      waitForExpect(async () => {
        expect(
          getEventByType(
            receiveTx as UserTransactionResponse,
            `${messageTransmitterClient.packageId}::${MoveModule.MessageTransmitter}::MessageReceived`
          )
        ).not.toBeNull();
        expect(
          getEventByType(
            receiveTx as UserTransactionResponse,
            `${tokenMessengerMinterClient.packageId}::${MoveModule.TokenMessenger}::MintAndWithdraw`
          )
        ).not.toBeNull();
      });

      console.log(`Received 1 USDC from EVM to APTOS: ${receiveTx.hash}`);

      // Send 1 USDC from APTOS to EVM
      const sendTx = await tokenMessengerMinterClient.depositForBurn(
        cctpPackagesFilePath,
        aptosUser,
        new U64(1),
        new U32(0),
        AccountAddress.from(evmUserAddress),
        stablecoinClient.getObjectAddress()
      );

      console.log(`Sent 1 USDC from APTOS to EVM: ${sendTx.hash}`);

      waitForExpect(async () => {
        expect(
          getEventByType(
            receiveTx as UserTransactionResponse,
            `${messageTransmitterClient.packageId}::${MoveModule.MessageTransmitter}::MessageSent`
          )
        ).not.toBeNull();
      });

      const messageSentEvent = getEventByType(
        sendTx as UserTransactionResponse,
        `${messageTransmitterClient.packageId}::${MoveModule.MessageTransmitter}::MessageSent`
      );

      const messageBytes = messageSentEvent.data.message;
      const attestation = attestToMessage(web3, messageBytes);

      await receiveEvm(evmUserAddress, contractDefinition, messageBytes, attestation);
    });

    test("Deposit For Burn with caller", async () => {
      const aptosUser = await generateFundedAccount(aptos);

      // Fund with USDC
      const mintTx = await tokenMessengerMinterClient.mint(
        cctpPackagesFilePath,
        secondaryMinter,
        new U64(1),
        aptosUser.accountAddress
      );
      expect(mintTx.success).toBe(true);

      // Send 1 USDC from APTOS to EVM
      const sendTx = await tokenMessengerMinterClient.depositForBurn(
        cctpPackagesFilePath,
        aptosUser,
        new U64(1),
        new U32(0),
        AccountAddress.from(evmUserAddress),
        stablecoinClient.getObjectAddress(),
        AccountAddress.from(evmUserAddress)
      );

      console.log(`Sent 1 USDC from APTOS to EVM: ${sendTx.hash}`);

      waitForExpect(async () => {
        expect(
          getEventByType(
            sendTx as UserTransactionResponse,
            `${messageTransmitterClient.packageId}::${MoveModule.MessageTransmitter}::MessageSent`
          )
        ).not.toBeNull();
      });

      const messageSentEvent = getEventByType(
        sendTx as UserTransactionResponse,
        `${messageTransmitterClient.packageId}::${MoveModule.MessageTransmitter}::MessageSent`
      );

      const messageBytes = messageSentEvent.data.message;
      const attestation = attestToMessage(web3, messageBytes);

      await receiveEvm(evmUserAddress, contractDefinition, messageBytes, attestation);
    });
  });
});
