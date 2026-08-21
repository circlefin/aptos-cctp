/**
 * Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { MessageTransmitterClientV2 } from "../../typescript/aptos/client/messageTransmitterClientV2";
import {
  Account,
  AccountAddress,
  Aptos,
  AptosApiError,
  Ed25519Account,
  MoveVector,
  U32,
  U64,
  U8,
  UserTransactionResponse,
} from "@aptos-labs/ts-sdk";
import { AptosExtensionsClient } from "../../typescript/aptos/client/aptosExtensionsClient";
import { CctpExtensionsClient } from "../../typescript/aptos/client/cctpExtensionsClient";
import { StablecoinHandlerClient } from "../../typescript/aptos/client/stablecoinHandlerClient";
import { Web3 } from "web3";
import * as ethutil from "@ethereumjs/util";
import { beforeAll, describe, expect, jest, test } from "@jest/globals";
import dotenv from "dotenv";
import { TokenMessengerMinterClientV2 } from "../../typescript/aptos/client/tokenMessengerMinterClientV2";
import {
  generateFundedAccount,
  getAptosClient,
  normalizeAddress,
} from "../../typescript/aptos/utils/helper";
import { StablecoinClient } from "../../typescript/aptos/client/stablecoinClient";
import { fail } from "node:assert";

type DepositForBurnEventData = {
  amount: string;
  burn_token: string;
  depositor: string;
  destination_caller: string;
  destination_domain: number;
  destination_token_messenger: string;
  hook_data: string;
  max_fee: string;
  min_finality_threshold: number;
  mint_recipient: string;
};

type MessageSentEventData = {
  message: string;
};

type MessageReceivedEventData = {
  caller: string;
  finality_threshold_executed: number;
  message_body: string;
  nonce: string;
  sender: string;
  source_domain: number;
};

type MintAndWithdrawEventData = {
  amount: string;
  fee_collected: string;
  mint_token: string;
  mint_recipient: string;
};

// =====================================================
// Helper Functions for V2 Message Serialization
// =====================================================

/**
 * Serialize a u32 value to big-endian bytes (4 bytes)
 */
function serializeU32(value: number): Uint8Array {
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  view.setUint32(0, value, false); // big-endian
  return new Uint8Array(buffer);
}

/**
 * Serialize a u256 value to big-endian bytes (32 bytes)
 */
function serializeU256(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Serialize an address to bytes (32 bytes, left-padded)
 */
function serializeAddress(address: string): Uint8Array {
  const normalized = address.replace("0x", "").padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(normalized.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Construct a V2 burn message
 * Format: version(4) | burnToken(32) | mintRecipient(32) | amount(32) | messageSender(32) |
 *         maxFee(32) | feeExecuted(32) | expirationBlock(32) | hookData(dynamic)
 */
function serializeBurnMessageV2(params: {
  version: number;
  burnToken: string;
  mintRecipient: string;
  amount: bigint;
  messageSender: string;
  maxFee: bigint;
  feeExecuted?: bigint;
  expirationBlock?: bigint;
  hookData?: Uint8Array;
}): Uint8Array {
  const parts: Uint8Array[] = [
    serializeU32(params.version),
    serializeAddress(params.burnToken),
    serializeAddress(params.mintRecipient),
    serializeU256(params.amount),
    serializeAddress(params.messageSender),
    serializeU256(params.maxFee),
    serializeU256(params.feeExecuted ?? BigInt(0)),
    serializeU256(params.expirationBlock ?? BigInt(0)),
  ];

  if (params.hookData && params.hookData.length > 0) {
    parts.push(params.hookData);
  }

  // Concatenate all parts
  const totalLength = parts.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Construct a V2 message envelope
 * Format: version(4) | sourceDomain(4) | destinationDomain(4) | nonce(32) | sender(32) |
 *         recipient(32) | destinationCaller(32) | minFinalityThreshold(4) |
 *         finalityThresholdExecuted(4) | messageBody(dynamic)
 */
function serializeMessageV2(params: {
  version: number;
  sourceDomain: number;
  destinationDomain: number;
  nonce: bigint;
  sender: string;
  recipient: string;
  destinationCaller: string;
  minFinalityThreshold: number;
  finalityThresholdExecuted?: number;
  messageBody: Uint8Array;
}): Uint8Array {
  const parts: Uint8Array[] = [
    serializeU32(params.version),
    serializeU32(params.sourceDomain),
    serializeU32(params.destinationDomain),
    serializeU256(params.nonce),
    serializeAddress(params.sender),
    serializeAddress(params.recipient),
    serializeAddress(params.destinationCaller),
    serializeU32(params.minFinalityThreshold),
    serializeU32(params.finalityThresholdExecuted ?? 0),
    params.messageBody,
  ];

  // Concatenate all parts
  const totalLength = parts.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Generate an attestation using the configured attester private key.
 * The message is hashed with keccak256 and signed with ECDSA.
 */
function generateAttestation(web3: Web3, messageBytes: Uint8Array): Uint8Array {
  // Read the attester key from the local test environment instead of source code.
  const attesterPrivateKey = process.env.ATTESTER_PRIVATE_KEY;
  if (!attesterPrivateKey) {
    throw new Error("ATTESTER_PRIVATE_KEY must be set to generate test attestations");
  }

  // Hash the message using keccak256
  const messageHex = "0x" + Buffer.from(messageBytes).toString("hex");
  const messageHash = web3.utils.keccak256(messageHex);

  // Sign the hash
  const signedMessage = ethutil.ecsign(
    Buffer.from(ethutil.toBytes(messageHash)),
    Buffer.from(ethutil.toBytes(attesterPrivateKey))
  );

  // Combine r, s, v into attestation
  const attestation = ethutil.toRpcSig(signedMessage.v, signedMessage.r, signedMessage.s);
  return new Uint8Array(Buffer.from(attestation.replace("0x", ""), "hex"));
}

jest.setTimeout(200_000);
dotenv.config();

describe("End to End Tests", () => {
  const cctpPackagesFilePath = "packages";
  const includedArtifacts = "sparse";
  const stablecoinFilePath = "stablecoin-aptos/packages";

  let deployer: Ed25519Account;
  let feeRecipient: Ed25519Account;
  let messageTransmitterClientV2: MessageTransmitterClientV2;
  let tokenMessengerMinterClientV2: TokenMessengerMinterClientV2;
  let aptosExtensionsClient: AptosExtensionsClient;
  let stablecoinClient: StablecoinClient;
  let cctpExtensionsClient: CctpExtensionsClient;
  let stablecoinHandlerClient: StablecoinHandlerClient;
  let web3: Web3;
  let aptos: Aptos;
  let secondaryMinterController: Ed25519Account;
  let secondaryMinter: Ed25519Account;

  const usdcContractAddress = `${process.env.EVM_USDC_ADDRESS}`;
  const evmTokenMessengerAddress = `${process.env.EVM_TOKEN_MESSENGER_ADDRESS}`;

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

  // Helper to get primary fungible store balance
  const getPrimaryStoreBalance = async (address: AccountAddress): Promise<bigint> => {
    try {
      const result = await aptos.view({
        payload: {
          function: "0x1::primary_fungible_store::balance",
          typeArguments: ["0x1::fungible_asset::Metadata"],
          functionArguments: [address.toString(), stablecoinClient.getObjectAddress().toString()],
        },
      });
      return BigInt(result[0] as string);
    } catch {
      return BigInt(0);
    }
  };

  const setupAptos = async () => {
    // Initialize web3 for attestation generation
    web3 = new Web3();
    aptos = getAptosClient();
    deployer = await generateFundedAccount(aptos);
    feeRecipient = await generateFundedAccount(aptos);
    messageTransmitterClientV2 = new MessageTransmitterClientV2(aptos, deployer);
    tokenMessengerMinterClientV2 = new TokenMessengerMinterClientV2(aptos, deployer);
    aptosExtensionsClient = new AptosExtensionsClient(aptos, deployer);
    cctpExtensionsClient = new CctpExtensionsClient(aptos, deployer);
    stablecoinClient = new StablecoinClient(aptos, deployer);
    stablecoinHandlerClient = new StablecoinHandlerClient(aptos, deployer);
    const { aptosExtensionsPackageId, stablecoinPackageId } = await setupStablecoinAndAptosExtensions();

    const cctpExtensionsPackageId = await cctpExtensionsClient.publishPackage(cctpPackagesFilePath, aptosExtensionsPackageId, includedArtifacts);

    const messageTransmitterPackageId = await messageTransmitterClientV2.publishPackage(
      cctpPackagesFilePath,
      aptosExtensionsPackageId,
      cctpExtensionsPackageId,
      includedArtifacts
    );

    const tokenMessengerMinterPackageId = await tokenMessengerMinterClientV2.publishPackage(
      cctpPackagesFilePath,
      aptosExtensionsPackageId,
      messageTransmitterPackageId,
      cctpExtensionsPackageId,
      includedArtifacts
    );

    await stablecoinHandlerClient.publishPackage(
      cctpPackagesFilePath,
      aptosExtensionsPackageId,
      stablecoinPackageId,
      cctpExtensionsPackageId,
      messageTransmitterPackageId,
      tokenMessengerMinterPackageId,
      includedArtifacts
    );

    // Initialize Message Transmitter
    const localDomain = new U32(9);
    const attester = AccountAddress.from(`${process.env.EVM_ATTESTER_ADDRESS}`);
    const maxMessageBodySize = new U64(8192);
    const version = new U32(1);
    await messageTransmitterClientV2.initializeState(localDomain, attester, maxMessageBodySize, version);
    console.log(`Message Transmitter initialized.\n`);

    // Initialize Token Messenger Minter
    const messageBodyVersion = new U32(1);
    await tokenMessengerMinterClientV2.initializeState(messageBodyVersion, deployer.accountAddress, feeRecipient.accountAddress);
    console.log(`Token Messenger Minter initialized.\n`);

    messageTransmitterClientV2.packageId = messageTransmitterPackageId;
    tokenMessengerMinterClientV2.packageId = tokenMessengerMinterPackageId;

    // Configure TokenMessengerMinter's signer as a minter for receiving messages
    // The TMM signer is what actually calls treasury::mint in the handler
    await stablecoinClient.configureController(deployer.accountAddress, tokenMessengerMinterClientV2.signerAddress());
    await stablecoinClient.configureMinter(deployer, new U64(100_000_000_000));

    secondaryMinterController = await generateFundedAccount(aptos);
    secondaryMinter = await generateFundedAccount(aptos);
    await stablecoinClient.configureController(
      secondaryMinterController.accountAddress,
      secondaryMinter.accountAddress
    );
    await stablecoinClient.configureMinter(secondaryMinterController, new U64(100_000_000));

    // Add ETH remote token messenger in Aptos (domain 0)
    await tokenMessengerMinterClientV2.addRemoteTokenMessenger(
      new U32(0),
      AccountAddress.from(`${process.env.EVM_TOKEN_MESSENGER_ADDRESS}`)
    );

    // Add remote token messenger for domain 1 (for testing different destination domain)
    await tokenMessengerMinterClientV2.addRemoteTokenMessenger(
      new U32(1),
      AccountAddress.from("0xABCDEF1234567890ABCDEF1234567890ABCDEF12")
    );

    // Link Token Pair in Aptos for domain 0
    await tokenMessengerMinterClientV2.linkTokenPair(
      stablecoinClient.getObjectAddress(),
      new U32(0),
      AccountAddress.from(usdcContractAddress)
    );

    // Link Token Pair in Aptos for domain 1
    await tokenMessengerMinterClientV2.linkTokenPair(
      stablecoinClient.getObjectAddress(),
      new U32(1),
      AccountAddress.from("0x5678901234567890567890123456789056789012")
    );

    // Set max burn amount per message
    await tokenMessengerMinterClientV2.setMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress(), new U64(100_000_000));

    // Register stablecoin handler for the stablecoin token
    await tokenMessengerMinterClientV2.registerHandler(
      stablecoinClient.getObjectAddress(),
      stablecoinHandlerClient.getObjectAddress()
    );
    console.log(`Handler registered for stablecoin.\n`);

    // Set minimum fee for stablecoin (1% fee = 100000 in 1/1000th basis point precision)
    // Formula: fee = (amount * min_fee) / 10,000,000
    // For 1%: min_fee = 100000, so fee = amount * 0.01
    await tokenMessengerMinterClientV2.setMinFee(stablecoinClient.getObjectAddress(), BigInt(100000));
    console.log(`Min fee set for stablecoin (1%).\n`);
  };

  beforeAll(async () => {
    await setupAptos();
  });

  describe("Admin Functions", () => {
    describe("MessageTransmitterV2 Client", () => {
      test("Enable & Disable Attester", async () => {
        // Enable attester
        const newAttester = Account.generate().accountAddress;
        const enableTx = await messageTransmitterClientV2.enableAttester(newAttester);
        expect(await messageTransmitterClientV2.isEnabledAttester(newAttester)).toBeTruthy();

        // Verify AttesterEnabled event emitted
        const enableEvent = messageTransmitterClientV2.getAttesterEnabledEvent(enableTx);
        expect(normalizeAddress(enableEvent.data.attester)).toBe(normalizeAddress(newAttester.toString()));

        // Verify random address is not enabled
        expect(
          await messageTransmitterClientV2.isEnabledAttester(messageTransmitterClientV2.getObjectAddress())
        ).toBeFalsy();

        // Disable attester
        const disableTx = await messageTransmitterClientV2.disableAttester(newAttester);
        expect(await messageTransmitterClientV2.isEnabledAttester(newAttester)).toBeFalsy();

        // Verify AttesterDisabled event emitted
        const disableEvent = messageTransmitterClientV2.getAttesterDisabledEvent(disableTx);
        expect(normalizeAddress(disableEvent.data.attester)).toBe(normalizeAddress(newAttester.toString()));
      });
      test("Get & Update Attester Manager", async () => {
        // Get original attester manager
        const originalAttesterManager = await messageTransmitterClientV2.getAttesterManager();
        expect(originalAttesterManager.toString()).toBe(deployer.accountAddress.toString());

        // Update attester manager
        const newAttesterManager = Account.generate().accountAddress;
        const updateTx = await messageTransmitterClientV2.updateAttesterManager(newAttesterManager);
        expect((await messageTransmitterClientV2.getAttesterManager()).toString()).toBe(newAttesterManager.toString());

        // Verify AttesterManagerUpdated event emitted
        const updateEvent = messageTransmitterClientV2.getAttesterManagerUpdatedEvent(updateTx);
        expect(normalizeAddress(updateEvent.data.previous_attester_manager)).toBe(normalizeAddress(originalAttesterManager.toString()));
        expect(normalizeAddress(updateEvent.data.new_attester_manager)).toBe(normalizeAddress(newAttesterManager.toString()));

        // Revert to original attester manager
        await messageTransmitterClientV2.updateAttesterManager(originalAttesterManager);
        expect((await messageTransmitterClientV2.getAttesterManager()).toString()).toBe(
          originalAttesterManager.toString()
        );
      });
      test("Get & Set Signature Threshold", async () => {
        // Get original signature threshold
        const originalSignatureThreshold = await messageTransmitterClientV2.getSignatureThreshold();
        expect(originalSignatureThreshold).toBe("1");

        // Set new signature threshold
        const newAttester = Account.generate().accountAddress;
        await messageTransmitterClientV2.enableAttester(newAttester);
        const setThresholdTx = await messageTransmitterClientV2.setSignatureThreshold(new U64(2));
        expect(await messageTransmitterClientV2.getSignatureThreshold()).toBe("2");

        // Verify SignatureThresholdUpdated event emitted
        const thresholdEvent = messageTransmitterClientV2.getSignatureThresholdUpdatedEvent(setThresholdTx);
        expect(thresholdEvent.data.old_signature_threshold).toBe(originalSignatureThreshold);
        expect(thresholdEvent.data.new_signature_threshold).toBe("2");

        // Revert to original signature threshold
        await messageTransmitterClientV2.setSignatureThreshold(new U64(Number(originalSignatureThreshold)));
        expect(await messageTransmitterClientV2.getSignatureThreshold()).toBe(originalSignatureThreshold);
        await messageTransmitterClientV2.disableAttester(newAttester);
      });
      test("Get & Set Max Message Body Size", async () => {
        // Get original max message body size
        const originalMaxMessageBodySize = await messageTransmitterClientV2.getMaxMessageBodySize();
        expect(originalMaxMessageBodySize).toBe("8192");

        // Set new max message body size
        const setMaxSizeTx = await messageTransmitterClientV2.setMaxMessageBodySize(4096);
        expect(await messageTransmitterClientV2.getMaxMessageBodySize()).toBe("4096");

        // Verify MaxMessageBodySizeUpdated event emitted
        const maxSizeEvent = messageTransmitterClientV2.getMaxMessageBodySizeUpdatedEvent(setMaxSizeTx);
        expect(maxSizeEvent.data.max_message_body_size).toBe("4096");

        // Revert to original max message body size
        await messageTransmitterClientV2.setMaxMessageBodySize(Number(originalMaxMessageBodySize));
        expect(await messageTransmitterClientV2.getMaxMessageBodySize()).toBe(originalMaxMessageBodySize);
      });
      test("Fetch States", async () => {
        // Get & Verify local_domain
        expect(await messageTransmitterClientV2.getLocalDomain()).toEqual(9);

        // Get & Verify version
        expect(await messageTransmitterClientV2.getVersion()).toEqual(1);

        // Get & Verify max_message_body_size
        expect(await messageTransmitterClientV2.getMaxMessageBodySize()).toEqual("8192");

        // Get & Verify signature_threshold
        expect(await messageTransmitterClientV2.getSignatureThreshold()).toEqual("1");

        // Get & Verify attester_manager
        expect((await messageTransmitterClientV2.getAttesterManager()).toString()).toBe(
          deployer.accountAddress.toString()
        );

        // Get & Verify num_enabled_attesters
        expect(await messageTransmitterClientV2.getNumEnabledAttesters()).toEqual("1");

        // Get & Verify enabled_attester
        expect((await messageTransmitterClientV2.getEnabledAttester(0)).toString().toLowerCase()).toBe(
          normalizeAddress(`${process.env.EVM_ATTESTER_ADDRESS}`).toLowerCase()
        );
      });
    });
    describe("TokenMessengerMinterV2 Client", () => {
      test("Add & Remove Remote Token Messenger", async () => {
        // Add remote token messenger
        const remoteDomain = new U32(2);
        const remoteTokenMessenger = Account.generate().accountAddress;
        const addTx = await tokenMessengerMinterClientV2.addRemoteTokenMessenger(remoteDomain, remoteTokenMessenger);

        // Verify remote token messenger was added
        const remoteTokenMessengerAddress = await tokenMessengerMinterClientV2.getRemoteTokenMessenger(remoteDomain);
        expect(remoteTokenMessengerAddress).toStrictEqual(remoteTokenMessenger);

        // Verify RemoteTokenMessengerAdded event emitted
        const addEvent = tokenMessengerMinterClientV2.getRemoteTokenMessengerAddedEvent(addTx);
        expect(addEvent.data.domain).toBe(2);
        expect(normalizeAddress(addEvent.data.token_messenger)).toBe(normalizeAddress(remoteTokenMessenger.toString()));

        // Remove remote token messenger
        const removeTx = await tokenMessengerMinterClientV2.removeRemoteTokenMessenger(remoteDomain);
        await expect(() => tokenMessengerMinterClientV2.getRemoteTokenMessenger(remoteDomain)).rejects.toThrow();

        // Verify RemoteTokenMessengerRemoved event emitted
        const removeEvent = tokenMessengerMinterClientV2.getRemoteTokenMessengerRemovedEvent(removeTx);
        expect(removeEvent.data.domain).toBe(2);
        expect(normalizeAddress(removeEvent.data.token_messenger)).toBe(normalizeAddress(remoteTokenMessenger.toString()));
      });
      describe("Token Controller", () => {
        test("Get & Set Token Controller", async () => {
          // Get original token controller manager
          const originalTokenController = await tokenMessengerMinterClientV2.getTokenController();
          expect(originalTokenController.toString()).toBe(deployer.accountAddress.toString());

          // Set new token controller
          const newTokenController = Account.generate().accountAddress;
          const setTx = await tokenMessengerMinterClientV2.setTokenController(newTokenController);
          expect((await tokenMessengerMinterClientV2.getTokenController()).toString()).toBe(newTokenController.toString());

          // Verify SetTokenController event emitted
          const setEvent = tokenMessengerMinterClientV2.getSetTokenControllerEvent(setTx);
          expect(normalizeAddress(setEvent.data.token_controller)).toBe(normalizeAddress(newTokenController.toString()));

          // Revert to original token controller
          await tokenMessengerMinterClientV2.setTokenController(originalTokenController);
          expect((await tokenMessengerMinterClientV2.getTokenController()).toString()).toBe(
            originalTokenController.toString()
          );
        });
        test("Get Linked Tokens", async () => {
          // Get & Verify get_linked_token
          expect(
            await tokenMessengerMinterClientV2.getLinkedToken(new U32(0), AccountAddress.from(usdcContractAddress))
          ).toEqual(stablecoinClient.getObjectAddress());

          // Get & Verify get_num_linked_tokens
          expect(await tokenMessengerMinterClientV2.getNumLinkedTokens()).toEqual("2");
        });
        test("Get & Set Max Burn Amount Per Message", async () => {
          // Get original max burn amount
          const originalMaxBurnMount = await tokenMessengerMinterClientV2.getMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress());
          expect(originalMaxBurnMount).toBe("100000000");

          // Set new max burn amount
          const setTx = await tokenMessengerMinterClientV2.setMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress(), new U64(2));
          expect((await tokenMessengerMinterClientV2.getMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress()))).toBe("2");

          // Verify SetBurnLimitPerMessage event emitted
          const setEvent = tokenMessengerMinterClientV2.getSetBurnLimitPerMessageEvent(setTx);
          expect(normalizeAddress(setEvent.data.token)).toBe(normalizeAddress(stablecoinClient.getObjectAddress().toString()));
          expect(setEvent.data.burn_limit_per_message).toBe("2");

          // Revert to original max burn amount
          await tokenMessengerMinterClientV2.setMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress(), new U64(Number(originalMaxBurnMount)));
          expect((await tokenMessengerMinterClientV2.getMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress()))).toBe("100000000");
        });
        test("Link & Unlink Token Pair", async () => {
          // Link token pair
          const localToken = stablecoinClient.getObjectAddress();
          const remoteDomain = new U32(2);
          const newRemoteToken = Account.generate().accountAddress;
          const linkTx = await tokenMessengerMinterClientV2.linkTokenPair(
            localToken,
            remoteDomain,
            AccountAddress.from(newRemoteToken)
          );

          // Get & Verify newly linked token
          expect(
            await tokenMessengerMinterClientV2.getLinkedToken(remoteDomain, AccountAddress.from(newRemoteToken))
          ).toEqual(localToken);

          // Verify TokenPairLinked event emitted
          const linkEvent = tokenMessengerMinterClientV2.getTokenPairLinkedEvent(linkTx);
          expect(normalizeAddress(linkEvent.data.local_token)).toBe(normalizeAddress(localToken.toString()));
          expect(linkEvent.data.remote_domain).toBe(2);
          expect(normalizeAddress(linkEvent.data.remote_token)).toBe(normalizeAddress(newRemoteToken.toString()));

          // Unlink token pair
          const unlinkTx = await tokenMessengerMinterClientV2.unlinkTokenPair(remoteDomain, AccountAddress.from(newRemoteToken));

          // Verify TokenPairUnlinked event emitted
          const unlinkEvent = tokenMessengerMinterClientV2.getTokenPairUnlinkedEvent(unlinkTx);
          expect(normalizeAddress(unlinkEvent.data.local_token)).toBe(normalizeAddress(localToken.toString()));
          expect(unlinkEvent.data.remote_domain).toBe(2);
          expect(normalizeAddress(unlinkEvent.data.remote_token)).toBe(normalizeAddress(newRemoteToken.toString()));

          // Get & Verify unlinked token
          try {
            await tokenMessengerMinterClientV2.getLinkedToken(
              remoteDomain,
              AccountAddress.from(newRemoteToken)
            );
            fail("Expected getLinkedToken to throw an error after unlinking");
          } catch (error) {
            expect(error).toBeInstanceOf(AptosApiError);
            expect(error.message).toContain("ENO_LINK_EXIST_FOR_REMOTE_DOMAIN_AND_TOKEN");
          }
        });
      });
      describe("Denylister", () => {
        test("Get & Update Denylister", async () => {
          // Get original denylister
          const originalDenylister = await tokenMessengerMinterClientV2.getDenylister();
          expect(originalDenylister.toString()).toBe(deployer.accountAddress.toString());

          // Update denylister
          const newDenylister = Account.generate().accountAddress;
          const updateTx = await tokenMessengerMinterClientV2.updateDenylister(newDenylister);
          expect((await tokenMessengerMinterClientV2.getDenylister()).toString()).toBe(newDenylister.toString());

          // Verify DenylisterChanged event
          const updateEvent = tokenMessengerMinterClientV2.getDenylisterChangedEvent(updateTx);
          expect(normalizeAddress(updateEvent.data.old_denylister)).toBe(normalizeAddress(originalDenylister.toString()));
          expect(normalizeAddress(updateEvent.data.new_denylister)).toBe(normalizeAddress(newDenylister.toString()));

          // Revert to original denylister
          await tokenMessengerMinterClientV2.updateDenylister(originalDenylister);
          expect((await tokenMessengerMinterClientV2.getDenylister()).toString()).toBe(
            originalDenylister.toString()
          );
        });
        test("Denylist & Undenylist", async () => {
          // Denylist
          const newAddress = Account.generate().accountAddress;
          const denylistTx = await tokenMessengerMinterClientV2.denylist(newAddress);
          expect(await tokenMessengerMinterClientV2.isDenylisted(newAddress)).toBeTruthy();

          // Verify Denylisted event emitted
          const denylistEvent = tokenMessengerMinterClientV2.getDenylistedEvent(denylistTx);
          expect(normalizeAddress(denylistEvent.data.address)).toBe(normalizeAddress(newAddress.toString()));

          // Verify random address is not denylisted
          expect(
            await tokenMessengerMinterClientV2.isDenylisted(tokenMessengerMinterClientV2.getObjectAddress())
          ).toBeFalsy();

          // UnDenylist
          const undenylistTx = await tokenMessengerMinterClientV2.undenylist(newAddress);
          expect(await tokenMessengerMinterClientV2.isDenylisted(newAddress)).toBeFalsy();

          // Verify UnDenylisted event emitted
          const undenylistEvent = tokenMessengerMinterClientV2.getUnDenylistedEvent(undenylistTx);
          expect(normalizeAddress(undenylistEvent.data.address)).toBe(normalizeAddress(newAddress.toString()));
        });
      });
      describe("Fee Controller", () => {
        test("Get & Set Fee Recipient", async () => {
          // Get original fee recipient
          const originalFeeRecipient = await tokenMessengerMinterClientV2.getFeeRecipient();
          expect(originalFeeRecipient.toString()).toBe(feeRecipient.accountAddress.toString());

          // Set new fee recipient
          const newFeeRecipient = Account.generate().accountAddress;
          const setTx = await tokenMessengerMinterClientV2.setFeeRecipient(newFeeRecipient);
          expect((await tokenMessengerMinterClientV2.getFeeRecipient()).toString()).toBe(newFeeRecipient.toString());

          // Verify FeeRecipientSet event emitted
          const setEvent = tokenMessengerMinterClientV2.getFeeRecipientSetEvent(setTx);
          expect(normalizeAddress(setEvent.data.address)).toBe(normalizeAddress(newFeeRecipient.toString()));

          // Revert to original fee recipient
          await tokenMessengerMinterClientV2.setFeeRecipient(originalFeeRecipient);
          expect((await tokenMessengerMinterClientV2.getFeeRecipient()).toString()).toBe(
            originalFeeRecipient.toString()
          );
        });
        test("Get & Set Min Fee Controller", async () => {
          // Get original min fee controller
          const originalMinFeeController = await tokenMessengerMinterClientV2.getMinFeeController();
          expect(originalMinFeeController.toString()).toBe(deployer.accountAddress.toString());

          // Set new min fee controller
          const newMinFeeController = Account.generate().accountAddress;
          const setTx = await tokenMessengerMinterClientV2.setMinFeeController(newMinFeeController);
          expect((await tokenMessengerMinterClientV2.getMinFeeController()).toString()).toBe(
            newMinFeeController.toString()
          );

          // Verify MinFeeControllerSet event emitted
          const setEvent = tokenMessengerMinterClientV2.getMinFeeControllerSetEvent(setTx);
          expect(normalizeAddress(setEvent.data.address)).toBe(normalizeAddress(newMinFeeController.toString()));

          // Revert to original min fee controller
          await tokenMessengerMinterClientV2.setMinFeeController(originalMinFeeController);
          expect((await tokenMessengerMinterClientV2.getMinFeeController()).toString()).toBe(
            originalMinFeeController.toString()
          );
        });
        test("Get & Set Min Fee", async () => {
          // Get min fee for stablecoin
          const tokenAddress = stablecoinClient.getObjectAddress();
          const initialMinFee = await tokenMessengerMinterClientV2.getMinFee(tokenAddress);
          expect(initialMinFee).toBe(BigInt(100000));

          // Set min fee to 200000
          const newMinFee = BigInt(200000);
          const setTx = await tokenMessengerMinterClientV2.setMinFee(tokenAddress, newMinFee);
          expect(await tokenMessengerMinterClientV2.getMinFee(tokenAddress)).toBe(BigInt(200000));

          // Verify MinFeeSet event emitted
          const setEvent = tokenMessengerMinterClientV2.getMinFeeSetEvent(setTx);
          expect(normalizeAddress(setEvent.data.token_address)).toBe(normalizeAddress(tokenAddress.toString()));
          expect(setEvent.data.min_fee).toBe("200000");

          // Revert to original min fee
          await tokenMessengerMinterClientV2.setMinFee(tokenAddress, BigInt(100000));
          expect(await tokenMessengerMinterClientV2.getMinFee(tokenAddress)).toBe(BigInt(100000));
        });
      });
      describe("Handler Registry", () => {
        test("Register & Deregister Handler", async () => {
          const tokenAddress = stablecoinClient.getObjectAddress();
          const handlerAddress = stablecoinHandlerClient.signerAddress();

          // Verify handler is registered initially
          expect(await tokenMessengerMinterClientV2.isHandlerRegistered(tokenAddress)).toBeTruthy();

          // Deregister handler
          const deregisterTx = await tokenMessengerMinterClientV2.deregisterHandler(tokenAddress);
          expect(await tokenMessengerMinterClientV2.isHandlerRegistered(tokenAddress)).toBeFalsy();

          // Verify HandlerDeregistered event
          const deregisterEvent = tokenMessengerMinterClientV2.getHandlerDeregisteredEvent(deregisterTx);
          expect(normalizeAddress(deregisterEvent.data.token_address)).toBe(normalizeAddress(tokenAddress.toString()));
          expect(normalizeAddress(deregisterEvent.data.handler_address)).toBe(normalizeAddress(handlerAddress.toString()));

          // Register handler
          const registerTx = await tokenMessengerMinterClientV2.registerHandler(tokenAddress, handlerAddress);
          expect(await tokenMessengerMinterClientV2.isHandlerRegistered(tokenAddress)).toBeTruthy();
          expect((await tokenMessengerMinterClientV2.getHandler(tokenAddress)).toString()).toBe(
            handlerAddress.toString()
          );

          // Verify HandlerRegistered event emitted
          const registerEvent = tokenMessengerMinterClientV2.getHandlerRegisteredEvent(registerTx);
          expect(normalizeAddress(registerEvent.data.token_address)).toBe(normalizeAddress(tokenAddress.toString()));
          expect(normalizeAddress(registerEvent.data.handler_address)).toBe(normalizeAddress(handlerAddress.toString()));
        });
      });
      test("Fetch states", async () => {
        // Get & Verify message_body_version
        expect(await tokenMessengerMinterClientV2.getMessageBodyVersion()).toEqual(1);

        // Get & Verify num_remote_token_messengers
        expect(await tokenMessengerMinterClientV2.getNumRemoteTokenMessenger()).toEqual("2");

        // Get & Verify remote_token_messenger for domain 0
        expect((await tokenMessengerMinterClientV2.getRemoteTokenMessenger(new U32(0))).toString().toLowerCase()).toBe(
          normalizeAddress(`${process.env.EVM_TOKEN_MESSENGER_ADDRESS}`).toLowerCase()
        );

        // Get & Verify num_linked_tokens
        expect(await tokenMessengerMinterClientV2.getNumLinkedTokens()).toEqual("2");

        // Get & Verify linked_token (local token from remote domain and token)
        expect(
          (await tokenMessengerMinterClientV2.getLinkedToken(new U32(0), AccountAddress.from(usdcContractAddress))).toString()
        ).toBe(stablecoinClient.getObjectAddress().toString());

        // Get & Verify max_burn_amount_per_message
        expect(await tokenMessengerMinterClientV2.getMaxBurnAmountPerMessage(stablecoinClient.getObjectAddress())).toEqual("100000000");

        // Get & Verify token_controller
        expect((await tokenMessengerMinterClientV2.getTokenController()).toString()).toBe(
          deployer.accountAddress.toString()
        );

        // Get & Verify fee_recipient
        expect((await tokenMessengerMinterClientV2.getFeeRecipient()).toString()).toBe(
          feeRecipient.accountAddress.toString()
        );

        // Get & Verify denylister
        expect((await tokenMessengerMinterClientV2.getDenylister()).toString()).toBe(
          deployer.accountAddress.toString()
        );

        // Get & Verify min_fee_controller
        expect((await tokenMessengerMinterClientV2.getMinFeeController()).toString()).toBe(
          deployer.accountAddress.toString()
        );
      });
    });
    describe("CctpExtensions Client", () => {
      let objectAddress: AccountAddress;
      beforeAll(async () => {
        objectAddress = tokenMessengerMinterClientV2.getObjectAddress();
      });
      describe("Rescuable", () => {
        test("Get & Update Rescuer", async () => {
          // Get original rescuer
          const originalRescuer = await cctpExtensionsClient.rescuer(objectAddress);
          expect(originalRescuer.toString()).toBe(deployer.accountAddress.toString());

          // Update rescuer to a new address
          const newRescuer = Account.generate().accountAddress;
          const updateTx = await cctpExtensionsClient.updateRescuer(deployer, objectAddress, newRescuer);

          // Verify rescuer was updated
          const updatedRescuer = await cctpExtensionsClient.rescuer(objectAddress);
          expect(updatedRescuer.toString()).toBe(newRescuer.toString());

          // Verify RescuerChanged event emitted
          const updateEvent = cctpExtensionsClient.getRescuerChangedEvent(updateTx);
          expect(normalizeAddress(updateEvent.data.obj_address)).toBe(normalizeAddress(objectAddress.toString()));
          expect(normalizeAddress(updateEvent.data.new_rescuer)).toBe(normalizeAddress(newRescuer.toString()));

          // Revert to original rescuer
          await cctpExtensionsClient.updateRescuer(deployer, objectAddress, originalRescuer);
          expect((await cctpExtensionsClient.rescuer(objectAddress)).toString()).toBe(
            originalRescuer.toString()
          );
        });
        test("Rescue Fungible Asset", async () => {
          const rescueAmount = 1000;
          const recipientAccount = await generateFundedAccount(aptos);
          const stablecoinMetadata = stablecoinClient.getObjectAddress();
          const initialRecipientBalance = await getPrimaryStoreBalance(recipientAccount.accountAddress);
          const initialTmmBalance = await getPrimaryStoreBalance(objectAddress);

          // Mint tokens directly to TMM contract to simulate stuck tokens
          const mintTx = await stablecoinHandlerClient.mint(
            cctpPackagesFilePath,
            secondaryMinter,
            new U64(rescueAmount),
            objectAddress
          );
          expect(mintTx.success).toBeTruthy();

          // Verify tokens are in the TMM contract
          const tmmBalanceAfterMint = await getPrimaryStoreBalance(objectAddress);
          expect(tmmBalanceAfterMint).toBe(initialTmmBalance + BigInt(rescueAmount));

          // Rescue the tokens
          await cctpExtensionsClient.rescueFungibleAsset(
            deployer,
            objectAddress,
            stablecoinMetadata,
            recipientAccount.accountAddress,
            rescueAmount
          );

          // Verify tokens were rescued to recipient
          const finalRecipientBalance = await getPrimaryStoreBalance(recipientAccount.accountAddress);
          expect(finalRecipientBalance).toBe(initialRecipientBalance + BigInt(rescueAmount));

          // Verify tokens were removed from TMM contract
          const tmmBalanceAfterRescue = await getPrimaryStoreBalance(objectAddress);
          expect(tmmBalanceAfterRescue).toBe(initialTmmBalance);
        });
      });
    });
    describe("StablecoinHandler Client", () => {
      test("Fetch States", async () => {
        // Get & Verify handler_address
        const handlerAddress = await stablecoinHandlerClient.getHandlerAddress();
        expect(handlerAddress.toString()).toBe(stablecoinHandlerClient.getObjectAddress().toString());

        // Get & Verify supported_token
        const supportedToken = await stablecoinHandlerClient.getSupportedToken();
        expect(supportedToken.toString()).toBe(stablecoinClient.getObjectAddress().toString());
      });
    });
    describe("AptosExtensions Client", () => {
      let objectAddress: AccountAddress;
      beforeAll(async () => {
        objectAddress = messageTransmitterClientV2.getObjectAddress();
      });
      test("Get & Update Pauser", async () => {
        // Get original pauser
        const initialPauser = await aptosExtensionsClient.pauser(objectAddress);
        expect(initialPauser.toString()).toBe(deployer.accountAddress.toString());

        // Update pauser
        const newPauser = Account.generate().accountAddress;
        const updateTx = await aptosExtensionsClient.updatePauser(deployer, objectAddress, newPauser);
        expect((await aptosExtensionsClient.pauser(objectAddress)).toString()).toBe(newPauser.toString());

        // Verify PauserChanged event emitted
        const updateEvent = aptosExtensionsClient.getPauserChangedEvent(updateTx);
        expect(normalizeAddress(updateEvent.data.obj_address)).toBe(normalizeAddress(objectAddress.toString()));
        expect(normalizeAddress(updateEvent.data.old_pauser)).toBe(normalizeAddress(initialPauser.toString()));
        expect(normalizeAddress(updateEvent.data.new_pauser)).toBe(normalizeAddress(newPauser.toString()));

        // Revert to original pauser
        await aptosExtensionsClient.updatePauser(deployer, objectAddress, deployer.accountAddress);
        expect((await aptosExtensionsClient.pauser(objectAddress)).toString()).toBe(initialPauser.toString());
      });
      test("Pause & Unpause & IsPaused", async () => {
        // Pause
        const pauseTx = await aptosExtensionsClient.pause(deployer, objectAddress);
        expect(await aptosExtensionsClient.isPaused(objectAddress)).toBeTruthy();

        // Verify Pause event emitted
        const pauseEvent = aptosExtensionsClient.getPauseEvent(pauseTx);
        expect(normalizeAddress(pauseEvent.data.obj_address)).toBe(normalizeAddress(objectAddress.toString()));

        // Unpause
        const unpauseTx = await aptosExtensionsClient.unpause(deployer, objectAddress);
        expect(await aptosExtensionsClient.isPaused(objectAddress)).toBeFalsy();

        // Verify Unpause event emitted
        const unpauseEvent = aptosExtensionsClient.getUnpauseEvent(unpauseTx);
        expect(normalizeAddress(unpauseEvent.data.obj_address)).toBe(normalizeAddress(objectAddress.toString()));
      });
      test("Transfer, Accept & Fetch Ownership", async () => {
        // Get original owner
        const originalOwner = await aptosExtensionsClient.owner(objectAddress);
        expect(originalOwner.toString()).toBe(deployer.accountAddress.toString());

        // Initiate owner transfer to new owner
        const newOwner = await generateFundedAccount(aptos);
        const transferTx = await aptosExtensionsClient.transferOwnership(deployer, objectAddress, newOwner.accountAddress);
        expect((await aptosExtensionsClient.pendingOwner(objectAddress)).toString()).toBe(
          newOwner.accountAddress.toString()
        );

        // Verify OwnershipTransferStarted event emitted
        const transferStartedEvent = aptosExtensionsClient.getOwnershipTransferStartedEvent(transferTx);
        expect(normalizeAddress(transferStartedEvent.data.obj_address)).toBe(normalizeAddress(objectAddress.toString()));
        expect(normalizeAddress(transferStartedEvent.data.old_owner)).toBe(normalizeAddress(deployer.accountAddress.toString()));
        expect(normalizeAddress(transferStartedEvent.data.new_owner)).toBe(normalizeAddress(newOwner.accountAddress.toString()));

        // Accept Ownership
        const acceptTx = await aptosExtensionsClient.acceptOwnership(newOwner, objectAddress);
        expect((await aptosExtensionsClient.owner(objectAddress)).toString()).toBe(newOwner.accountAddress.toString());
        expect(await aptosExtensionsClient.pendingOwner(objectAddress)).toBe("");

        // Verify OwnershipTransferred event emitted
        const transferredEvent = aptosExtensionsClient.getOwnershipTransferredEvent(acceptTx);
        expect(normalizeAddress(transferredEvent.data.obj_address)).toBe(normalizeAddress(objectAddress.toString()));
        expect(normalizeAddress(transferredEvent.data.old_owner)).toBe(normalizeAddress(deployer.accountAddress.toString()));
        expect(normalizeAddress(transferredEvent.data.new_owner)).toBe(normalizeAddress(newOwner.accountAddress.toString()));

        // Revert to the original owner (deployer)
        await aptosExtensionsClient.transferOwnership(newOwner, objectAddress, deployer.accountAddress);
        await aptosExtensionsClient.acceptOwnership(deployer, objectAddress);
        expect((await aptosExtensionsClient.owner(objectAddress)).toString()).toBe(deployer.accountAddress.toString());
        expect(await aptosExtensionsClient.pendingOwner(objectAddress)).toBe("");
      });
      test("Change, Accept & Fetch Admin", async () => {
        // Get original admin
        const handlerPackageId = messageTransmitterClientV2.packageId;
        const originalAdmin = await aptosExtensionsClient.admin(handlerPackageId);
        expect(originalAdmin.toString()).toBe(deployer.accountAddress.toString());

        // Initiate admin change to new admin
        const newAdmin = await generateFundedAccount(aptos);
        const changeAdminTx = await aptosExtensionsClient.changeAdmin(deployer, handlerPackageId, newAdmin.accountAddress);
        expect((await aptosExtensionsClient.pendingAdmin(handlerPackageId)).toString()).toBe(
          newAdmin.accountAddress.toString()
        );

        // Verify AdminChangeStarted event emitted
        const changeStartedEvent = aptosExtensionsClient.getAdminChangeStartedEvent(changeAdminTx);
        expect(normalizeAddress(changeStartedEvent.data.resource_address)).toBe(normalizeAddress(handlerPackageId));
        expect(normalizeAddress(changeStartedEvent.data.old_admin)).toBe(normalizeAddress(deployer.accountAddress.toString()));
        expect(normalizeAddress(changeStartedEvent.data.new_admin)).toBe(normalizeAddress(newAdmin.accountAddress.toString()));

        // Accept admin
        const acceptAdminTx = await aptosExtensionsClient.acceptAdmin(newAdmin, handlerPackageId);
        expect((await aptosExtensionsClient.admin(handlerPackageId)).toString()).toBe(newAdmin.accountAddress.toString());
        expect(await aptosExtensionsClient.pendingAdmin(handlerPackageId)).toBe("");

        // Verify AdminChanged event emitted
        const adminChangedEvent = aptosExtensionsClient.getAdminChangedEvent(acceptAdminTx);
        expect(normalizeAddress(adminChangedEvent.data.resource_address)).toBe(normalizeAddress(handlerPackageId));
        expect(normalizeAddress(adminChangedEvent.data.old_admin)).toBe(normalizeAddress(deployer.accountAddress.toString()));
        expect(normalizeAddress(adminChangedEvent.data.new_admin)).toBe(normalizeAddress(newAdmin.accountAddress.toString()));

        // Revert to the original admin (deployer)
        await aptosExtensionsClient.changeAdmin(newAdmin, handlerPackageId, deployer.accountAddress);
        await aptosExtensionsClient.acceptAdmin(deployer, handlerPackageId);
        expect((await aptosExtensionsClient.admin(handlerPackageId)).toString()).toBe(deployer.accountAddress.toString());
        expect(await aptosExtensionsClient.pendingAdmin(handlerPackageId)).toBe("");
      });
      test("Upgrade requires permission", async () => {
        // Non-admin should not be able to upgrade
        const randomAccount = await generateFundedAccount(aptos);
        const dummyMetadata = "0x00"; // Dummy metadata
        const dummyBytecode = ["0x00"]; // Dummy bytecode

        try {
          await aptosExtensionsClient.upgradePackage(
            randomAccount,
            messageTransmitterClientV2.packageId,
            dummyMetadata,
            dummyBytecode
          );
          fail("Expected upgrade to fail for non-admin account");
        } catch (error) {
          const errorMessage = error.message || String(error);
          expect(errorMessage).toContain("ENOT_ADMIN");
        }
      });
    });
  });

  describe("E2E Tests", () => {
    test("APTOS -> EVM: deposit_for_burn", async () => {
      // Test parameters with non-zero values
      const user = await generateFundedAccount(aptos);
      const amount = 10000;
      const destinationDomain = 1;
      const evmRecipient = "0x1234567890123456789012345678901234567890";
      const destinationCaller = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12";
      // maxFee must be >= min_fee_amount = (amount * 100000) / 10000000 = amount * 1% = 100
      const maxFee = 100;
      const minFinalityThreshold = 1000;

      // 1. Mint tokens to user
      const mintTx = await stablecoinHandlerClient.mint(
        cctpPackagesFilePath,
        secondaryMinter,
        new U64(amount),
        user.accountAddress
      );
      expect(mintTx.success).toBe(true);
      console.log(`Minted ${amount} USDC to user: ${mintTx.hash}`);

      // 2. Verify initial balance
      const initialBalance = await getPrimaryStoreBalance(user.accountAddress);
      expect(initialBalance).toBe(BigInt(amount));
      console.log(`Initial balance: ${initialBalance}`);

      // 3. Execute deposit_for_burn
      const depositTx = await stablecoinHandlerClient.depositForBurn(
        cctpPackagesFilePath,
        user,
        new U64(amount),
        new U32(destinationDomain),
        AccountAddress.from(normalizeAddress(evmRecipient)),
        AccountAddress.from(normalizeAddress(destinationCaller)),
        stablecoinClient.getObjectAddress(),
        new U64(maxFee),
        new U32(minFinalityThreshold)
      );

      expect(depositTx.success).toBe(true);
      console.log(`Deposit for burn tx: ${depositTx.hash}`);

      // 4. Verify balance decreased to 0
      const finalBalance = await getPrimaryStoreBalance(user.accountAddress);
      expect(finalBalance).toBe(BigInt(0));
      console.log(`Final balance: ${finalBalance}`);

      // 5. Verify events
      const txResponse = depositTx as UserTransactionResponse;
      const depositForBurnEvent = txResponse.events.find(e => e.type.includes("::token_messenger_minter::DepositForBurn"));
      expect(depositForBurnEvent).toBeDefined();
      console.log("DepositForBurn event:", JSON.stringify(depositForBurnEvent, null, 2));

      // Verify DepositForBurn event fields
      // Note: Aptos may drop leading zeros in address representation
      const depositEventData = (depositForBurnEvent as { data: DepositForBurnEventData }).data;
      expect(depositEventData.amount).toBe(amount.toString());
      // burn_token is the stablecoin's object address
      expect(
        depositEventData.burn_token.toLowerCase().replace(/^0x0*/, "0x")
      ).toBe(
        stablecoinClient.getObjectAddress().toString().toLowerCase().replace(/^0x0*/, "0x")
      );
      expect(
        depositEventData.depositor.toLowerCase().replace(/^0x0*/, "0x")
      ).toBe(
        user.accountAddress.toString().toLowerCase().replace(/^0x0*/, "0x")
      );
      expect(depositEventData.destination_caller.toLowerCase()).toBe(destinationCaller.toLowerCase());
      expect(depositEventData.destination_domain).toBe(destinationDomain);
      // destination_token_messenger is the registered remote token messenger for domain 1
      expect(depositEventData.destination_token_messenger.toLowerCase()).toBe(destinationCaller.toLowerCase());
      expect(depositEventData.hook_data).toBe("0x"); // Empty for regular deposit
      expect(depositEventData.max_fee).toBe(maxFee.toString());
      expect(depositEventData.min_finality_threshold).toBe(minFinalityThreshold);
      expect(depositEventData.mint_recipient.toLowerCase()).toBe(evmRecipient.toLowerCase());

      const messageSentEvent = txResponse.events.find(e => e.type.includes("::message_transmitter::MessageSent"));
      expect(messageSentEvent).toBeDefined();
      console.log("MessageSent event:", JSON.stringify(messageSentEvent, null, 2));

      // Construct expected message and verify exact match
      // Message format: version(4) | sourceDomain(4) | destDomain(4) | nonce(32) | sender(32) |
      //                 recipient(32) | destCaller(32) | minFinalityThreshold(4) | finalityThresholdExecuted(4) | messageBody
      const burnMessageBody = serializeBurnMessageV2({
        version: 1,
        burnToken: stablecoinClient.getObjectAddress().toString(),
        mintRecipient: evmRecipient,
        amount: BigInt(amount),
        messageSender: user.accountAddress.toString(),
        maxFee: BigInt(maxFee),
        feeExecuted: BigInt(0),
        expirationBlock: BigInt(0),
      });

      const expectedMessage = serializeMessageV2({
        version: 1,
        sourceDomain: 9, // Aptos domain
        destinationDomain: destinationDomain,
        nonce: BigInt(0), // Outbound messages always have nonce = 0
        sender: tokenMessengerMinterClientV2.signerAddress().toString(),
        recipient: normalizeAddress(destinationCaller), // destination token messenger
        destinationCaller: normalizeAddress(destinationCaller),
        minFinalityThreshold: minFinalityThreshold,
        finalityThresholdExecuted: 0,
        messageBody: burnMessageBody,
      });

      const expectedMessageHex = "0x" + Buffer.from(expectedMessage).toString("hex");
      expect((messageSentEvent as { data: MessageSentEventData }).data.message).toBe(expectedMessageHex);
    });

    test("APTOS -> EVM: deposit_for_burn with zero destinationCaller", async () => {
      // Test with zero destinationCaller - allows any caller to execute on destination
      const user = await generateFundedAccount(aptos);
      const amount = 5000;
      const destinationDomain = 1;
      const evmRecipient = "0x1234567890123456789012345678901234567890";
      const zeroDestinationCaller = "0x0000000000000000000000000000000000000000";
      const maxFee = 50; // 1% of 5000
      const minFinalityThreshold = 500;

      // 1. Mint tokens to user
      const mintTx = await stablecoinHandlerClient.mint(
        cctpPackagesFilePath,
        secondaryMinter,
        new U64(amount),
        user.accountAddress
      );
      expect(mintTx.success).toBe(true);

      // 2. Execute deposit_for_burn with zero destinationCaller
      const depositTx = await stablecoinHandlerClient.depositForBurn(
        cctpPackagesFilePath,
        user,
        new U64(amount),
        new U32(destinationDomain),
        AccountAddress.from(normalizeAddress(evmRecipient)),
        AccountAddress.from(zeroDestinationCaller),
        stablecoinClient.getObjectAddress(),
        new U64(maxFee),
        new U32(minFinalityThreshold)
      );
      expect(depositTx.success).toBe(true);
      console.log(`Deposit for burn (zero caller) tx: ${depositTx.hash}`);

      // 3. Verify events
      const txResponse = depositTx as UserTransactionResponse;
      const depositForBurnEvent = txResponse.events.find(e => e.type.includes("::token_messenger_minter::DepositForBurn"));
      expect(depositForBurnEvent).toBeDefined();

      // Verify destinationCaller is zero in the event
      // Note: Aptos may return "0x0" for zero address instead of full form
      const depositEventData = (depositForBurnEvent as { data: DepositForBurnEventData }).data;
      expect(
        depositEventData.destination_caller.toLowerCase().replace(/^0x0*/, "0x")
      ).toBe("0x");

      const messageSentEvent = txResponse.events.find(e => e.type.includes("::message_transmitter::MessageSent"));
      expect(messageSentEvent).toBeDefined();

      // Construct expected message with zero destinationCaller
      const burnMessageBody = serializeBurnMessageV2({
        version: 1,
        burnToken: stablecoinClient.getObjectAddress().toString(),
        mintRecipient: evmRecipient,
        amount: BigInt(amount),
        messageSender: user.accountAddress.toString(),
        maxFee: BigInt(maxFee),
        feeExecuted: BigInt(0),
        expirationBlock: BigInt(0),
      });

      // Remote token messenger for domain 1 is 0xABCDEF...
      const remoteTokenMessenger = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12";
      const expectedMessage = serializeMessageV2({
        version: 1,
        sourceDomain: 9,
        destinationDomain: destinationDomain,
        nonce: BigInt(0), // Outbound messages always have nonce = 0
        sender: tokenMessengerMinterClientV2.signerAddress().toString(),
        recipient: normalizeAddress(remoteTokenMessenger),
        destinationCaller: zeroDestinationCaller, // Zero caller
        minFinalityThreshold: minFinalityThreshold,
        finalityThresholdExecuted: 0,
        messageBody: burnMessageBody,
      });

      const expectedMessageHex = "0x" + Buffer.from(expectedMessage).toString("hex");
      expect((messageSentEvent as { data: MessageSentEventData }).data.message).toBe(expectedMessageHex);
    });

    test("APTOS -> EVM: deposit_for_burn_with_hook", async () => {
      // Test parameters with non-zero values
      const user = await generateFundedAccount(aptos);
      const amount = 10000;
      const destinationDomain = 1;
      const evmRecipient = "0x1234567890123456789012345678901234567890";
      const destinationCaller = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12";
      // maxFee must be >= min_fee_amount = (amount * 100000) / 10000000 = amount * 1% = 100
      const maxFee = 100;
      const minFinalityThreshold = 1000;
      const hookData = Buffer.from("test_hook_data_for_v2_bridging");
      const hookDataHex = "0x" + hookData.toString("hex");

      // 1. Mint tokens to user
      const mintTx = await stablecoinHandlerClient.mint(
        cctpPackagesFilePath,
        secondaryMinter,
        new U64(amount),
        user.accountAddress
      );
      expect(mintTx.success).toBe(true);
      console.log(`Minted ${amount} USDC to user: ${mintTx.hash}`);

      // 2. Verify initial balance
      const initialBalance = await getPrimaryStoreBalance(user.accountAddress);
      expect(initialBalance).toBe(BigInt(amount));
      console.log(`Initial balance: ${initialBalance}`);

      // 3. Execute deposit_for_burn_with_hook
      const depositTx = await stablecoinHandlerClient.depositForBurnWithHook(
        cctpPackagesFilePath,
        user,
        new U64(amount),
        new U32(destinationDomain),
        AccountAddress.from(normalizeAddress(evmRecipient)),
        AccountAddress.from(normalizeAddress(destinationCaller)),
        stablecoinClient.getObjectAddress(),
        new U64(maxFee),
        new U32(minFinalityThreshold),
        MoveVector.U8(hookData)
      );

      expect(depositTx.success).toBe(true);
      console.log(`Deposit for burn with hook tx: ${depositTx.hash}`);

      // 4. Verify balance decreased to 0
      const finalBalance = await getPrimaryStoreBalance(user.accountAddress);
      expect(finalBalance).toBe(BigInt(0));
      console.log(`Final balance: ${finalBalance}`);

      // 5. Verify events
      const txResponse = depositTx as UserTransactionResponse;
      const depositForBurnEvent = txResponse.events.find(e => e.type.includes("::token_messenger_minter::DepositForBurn"));
      expect(depositForBurnEvent).toBeDefined();
      console.log("DepositForBurn event with hook_data:", JSON.stringify(depositForBurnEvent, null, 2));

      // Verify DepositForBurn event fields including hook_data
      // Note: Aptos may drop leading zeros in address representation
      const depositEventData = (depositForBurnEvent as { data: DepositForBurnEventData }).data;
      expect(depositEventData.amount).toBe(amount.toString());
      // burn_token is the stablecoin's object address
      expect(
        depositEventData.burn_token.toLowerCase().replace(/^0x0*/, "0x")
      ).toBe(
        stablecoinClient.getObjectAddress().toString().toLowerCase().replace(/^0x0*/, "0x")
      );
      expect(
        depositEventData.depositor.toLowerCase().replace(/^0x0*/, "0x")
      ).toBe(
        user.accountAddress.toString().toLowerCase().replace(/^0x0*/, "0x")
      );
      expect(depositEventData.destination_caller.toLowerCase()).toBe(destinationCaller.toLowerCase());
      expect(depositEventData.destination_domain).toBe(destinationDomain);
      // destination_token_messenger is the registered remote token messenger for domain 1
      expect(depositEventData.destination_token_messenger.toLowerCase()).toBe(destinationCaller.toLowerCase());
      expect(depositEventData.hook_data).toBe(hookDataHex);
      expect(depositEventData.max_fee).toBe(maxFee.toString());
      expect(depositEventData.min_finality_threshold).toBe(minFinalityThreshold);
      expect(depositEventData.mint_recipient.toLowerCase()).toBe(evmRecipient.toLowerCase());

      const messageSentEvent = txResponse.events.find(e => e.type.includes("::message_transmitter::MessageSent"));
      expect(messageSentEvent).toBeDefined();
      console.log("MessageSent event:", JSON.stringify(messageSentEvent, null, 2));

      // Construct expected message and verify exact match (includes hook_data)
      const burnMessageBody = serializeBurnMessageV2({
        version: 1,
        burnToken: stablecoinClient.getObjectAddress().toString(),
        mintRecipient: evmRecipient,
        amount: BigInt(amount),
        messageSender: user.accountAddress.toString(),
        maxFee: BigInt(maxFee),
        feeExecuted: BigInt(0),
        expirationBlock: BigInt(0),
        hookData: hookData,
      });

      const expectedMessage = serializeMessageV2({
        version: 1,
        sourceDomain: 9, // Aptos domain
        destinationDomain: destinationDomain,
        nonce: BigInt(0), // Outbound messages always have nonce = 0
        sender: tokenMessengerMinterClientV2.signerAddress().toString(),
        recipient: normalizeAddress(destinationCaller),
        destinationCaller: normalizeAddress(destinationCaller),
        minFinalityThreshold: minFinalityThreshold,
        finalityThresholdExecuted: 0,
        messageBody: burnMessageBody,
      });

      const expectedMessageHex = "0x" + Buffer.from(expectedMessage).toString("hex");
      expect((messageSentEvent as { data: MessageSentEventData }).data.message).toBe(expectedMessageHex);
    });

    test("APTOS -> EVM: send_message (general message)", async () => {
      // Test sending a general message (not a burn message)
      const sender = await generateFundedAccount(aptos);
      const destinationDomain = 1;
      const recipient = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12";
      const destinationCaller = "0x5678901234567890567890123456789056789012";
      const minFinalityThreshold = 500;
      const messageBody = Buffer.from("Hello from Aptos! This is a test message for CCTP V2.");

      // Execute send_message via StablecoinHandler script
      const sendTx = await stablecoinHandlerClient.sendMessage(
        cctpPackagesFilePath,
        sender,
        new U32(destinationDomain),
        AccountAddress.from(normalizeAddress(recipient)),
        AccountAddress.from(normalizeAddress(destinationCaller)),
        new U32(minFinalityThreshold),
        MoveVector.U8(messageBody)
      );

      expect(sendTx.success).toBe(true);
      console.log(`Send message tx: ${sendTx.hash}`);

      // Verify MessageSent event
      const txResponse = sendTx as UserTransactionResponse;
      const messageSentEvent = txResponse.events.find(e => e.type.includes("::message_transmitter::MessageSent"));
      expect(messageSentEvent).toBeDefined();
      console.log("MessageSent event:", JSON.stringify(messageSentEvent, null, 2));

      // Construct expected message and verify exact match
      const expectedMessage = serializeMessageV2({
        version: 1,
        sourceDomain: 9, // Aptos domain
        destinationDomain: destinationDomain,
        nonce: BigInt(0), // Outbound messages always have nonce = 0
        sender: sender.accountAddress.toString(),
        recipient: normalizeAddress(recipient),
        destinationCaller: normalizeAddress(destinationCaller),
        minFinalityThreshold: minFinalityThreshold,
        finalityThresholdExecuted: 0,
        messageBody: messageBody,
      });

      const expectedMessageHex = "0x" + Buffer.from(expectedMessage).toString("hex");
      expect((messageSentEvent as { data: MessageSentEventData }).data.message).toBe(expectedMessageHex);
    });

    test("EVM -> APTOS: receive_message", async () => {
      // Test parameters with non-zero values
      const user = await generateFundedAccount(aptos);
      const amount = BigInt(1000);
      const maxFee = BigInt(100);
      // Fee is calculated based on min_fee setting (1% = 100000)
      // fee = (amount * min_fee) / 10000000 = (1000 * 100000) / 10000000 = 10
      const expectedFee = BigInt(10);
      const expirationBlock = BigInt(999999999);
      const minFinalityThreshold = 500;
      const finalityThresholdExecuted = 2000;

      console.log(`User address: ${user.accountAddress.toString()}`);
      console.log(`Fee recipient address: ${feeRecipient.accountAddress.toString()}`);

      // 1. Get initial balances for both recipient and fee recipient
      const initialBalance = await getPrimaryStoreBalance(user.accountAddress);
      const initialFeeRecipientBalance = await getPrimaryStoreBalance(feeRecipient.accountAddress);
      console.log(`Initial balance: ${initialBalance}`);
      console.log(`Initial fee recipient balance: ${initialFeeRecipientBalance}`);

      // 2. Construct burn message with non-zero values
      // The fee_executed field in the burn message determines the actual fee collected
      const burnMessage = serializeBurnMessageV2({
        version: 1,
        burnToken: usdcContractAddress,
        mintRecipient: user.accountAddress.toString(),
        amount: amount,
        messageSender: normalizeAddress("0x1234567890123456789012345678901234567890"),
        maxFee: maxFee,
        feeExecuted: expectedFee, // This determines the fee collected on receive
        expirationBlock: expirationBlock,
      });

      // 3. Construct full V2 message envelope with non-zero values
      const randomNonce = BigInt(Math.floor(Math.random() * 1000000000));
      const message = serializeMessageV2({
        version: 1,
        sourceDomain: 0, // EVM domain
        destinationDomain: 9, // Aptos domain
        nonce: randomNonce,
        sender: evmTokenMessengerAddress,
        recipient: tokenMessengerMinterClientV2.getObjectAddress().toString(),
        destinationCaller: "0x0", // Anyone can call (deployer in this test)
        minFinalityThreshold: minFinalityThreshold,
        finalityThresholdExecuted: finalityThresholdExecuted,
        messageBody: burnMessage,
      });

      console.log(`Message length: ${message.length} bytes`);
      console.log(`Message hex: 0x${Buffer.from(message).toString("hex")}`);

      // 4. Generate attestation
      const attestation = generateAttestation(web3, message);
      console.log(`Attestation hex: 0x${Buffer.from(attestation).toString("hex")}`);

      // 5. Execute receive_message
      const receiveTx = await stablecoinHandlerClient.receiveMessage(
        cctpPackagesFilePath,
        deployer,
        MoveVector.U8(message),
        MoveVector.U8(attestation)
      );

      expect(receiveTx.success).toBe(true);
      console.log(`Receive message tx: ${receiveTx.hash}`);

      // 6. Verify recipient balance increased by (amount - fee)
      // Note: In CCTP V2, recipient receives (amount - fee_executed) from the burn message,
      // and fee_recipient receives fee_executed separately (total minted = amount)
      const finalBalance = await getPrimaryStoreBalance(user.accountAddress);
      const expectedBalance = initialBalance + (amount - expectedFee);
      expect(finalBalance).toBe(expectedBalance);
      console.log(`Final balance: ${finalBalance} (expected: ${expectedBalance})`);

      // 7. Verify fee recipient balance increased by fee_executed
      const finalFeeRecipientBalance = await getPrimaryStoreBalance(feeRecipient.accountAddress);
      const expectedFeeRecipientBalance = initialFeeRecipientBalance + expectedFee;
      expect(finalFeeRecipientBalance).toBe(expectedFeeRecipientBalance);
      console.log(`Final fee recipient balance: ${finalFeeRecipientBalance} (expected: ${expectedFeeRecipientBalance})`);

      // 8. Verify events
      const txResponse = receiveTx as UserTransactionResponse;
      console.log("All receive events:", txResponse.events.map(e => e.type));

      const messageReceivedEvent = txResponse.events.find(e => e.type.includes("::message_transmitter::MessageReceived"));
      expect(messageReceivedEvent).toBeDefined();
      console.log("MessageReceived event:", JSON.stringify(messageReceivedEvent, null, 2));

      // Verify MessageReceived event with full object comparison
      expect((messageReceivedEvent as { data: MessageReceivedEventData }).data).toEqual(expect.objectContaining({
        caller: expect.any(String),
        finality_threshold_executed: finalityThresholdExecuted,
        message_body: expect.stringMatching(/^0x[0-9a-f]+$/i),
        nonce: randomNonce.toString(),
        sender: expect.any(String),
        source_domain: 0,
      }));

      const mintAndWithdrawEvent = txResponse.events.find(e => e.type.includes("::token_messenger_minter::MintAndWithdraw"));
      expect(mintAndWithdrawEvent).toBeDefined();
      console.log("MintAndWithdraw event:", JSON.stringify(mintAndWithdrawEvent, null, 2));

      // Verify MintAndWithdraw event with full object comparison
      // Note: Aptos may drop leading zeros in address representation
      // amount = tokens deposited to recipient (amount - fee from burn message)
      // fee_collected = tokens deposited to fee_recipient (fee_executed from burn message)
      const mintEventData = (mintAndWithdrawEvent as { data: MintAndWithdrawEventData }).data;
      expect(mintEventData.amount).toBe((amount - expectedFee).toString());
      expect(mintEventData.fee_collected).toBe(expectedFee.toString());
      expect(
        mintEventData.mint_token.toLowerCase().replace(/^0x0*/, "0x")
      ).toBe(
        stablecoinClient.getObjectAddress().toString().toLowerCase().replace(/^0x0*/, "0x")
      );
      // Compare addresses case-insensitively and handle leading zeros
      expect(
        mintEventData.mint_recipient.toLowerCase().replace(/^0x0*/, "0x")
      ).toBe(
        user.accountAddress.toString().toLowerCase().replace(/^0x0*/, "0x")
      );

      // 9. Verify nonce is marked as used
      const isNonceUsed = await aptos.view({
        payload: {
          function: `${messageTransmitterClientV2.packageId}::message_transmitter::is_nonce_used`,
          typeArguments: [],
          functionArguments: [randomNonce.toString()],
        },
      });
      expect(isNonceUsed[0]).toBe(true);
      console.log(`Nonce ${randomNonce} is marked as used: ${isNonceUsed[0]}`);

      // 10. Verify a different nonce is not used
      const unusedNonce = randomNonce + BigInt(1);
      const isUnusedNonceUsed = await aptos.view({
        payload: {
          function: `${messageTransmitterClientV2.packageId}::message_transmitter::is_nonce_used`,
          typeArguments: [],
          functionArguments: [unusedNonce.toString()],
        },
      });
      expect(isUnusedNonceUsed[0]).toBe(false);
      console.log(`Nonce ${unusedNonce} is not used: ${isUnusedNonceUsed[0]}`);
    });

    test("EVM -> APTOS: receive_message with expired message", async () => {
      const user = await generateFundedAccount(aptos);
      const amount = BigInt(1000);
      const maxFee = BigInt(100);
      const expectedFee = BigInt(10);
      const expirationBlock = BigInt(1); // Expired message
      const minFinalityThreshold = 500;
      const finalityThresholdExecuted = 2000;

      console.log(`User address: ${user.accountAddress.toString()}`);
      console.log(`Fee recipient address: ${feeRecipient.accountAddress.toString()}`);

      // 1. Construct burn message with non-zero values
      // The fee_executed field in the burn message determines the actual fee collected
      const burnMessage = serializeBurnMessageV2({
        version: 1,
        burnToken: usdcContractAddress,
        mintRecipient: user.accountAddress.toString(),
        amount: amount,
        messageSender: normalizeAddress("0x1234567890123456789012345678901234567890"),
        maxFee: maxFee,
        feeExecuted: expectedFee, // This determines the fee collected on receive
        expirationBlock: expirationBlock,
      });

      // 2. Construct full V2 message envelope with non-zero values
      const randomNonce = BigInt(Math.floor(Math.random() * 1000000000));
      const message = serializeMessageV2({
        version: 1,
        sourceDomain: 0, // EVM domain
        destinationDomain: 9, // Aptos domain
        nonce: randomNonce,
        sender: evmTokenMessengerAddress,
        recipient: tokenMessengerMinterClientV2.getObjectAddress().toString(),
        destinationCaller: "0x0", // Anyone can call (deployer in this test)
        minFinalityThreshold: minFinalityThreshold,
        finalityThresholdExecuted: finalityThresholdExecuted,
        messageBody: burnMessage,
      });

      console.log(`Message length: ${message.length} bytes`);
      console.log(`Message hex: 0x${Buffer.from(message).toString("hex")}`);

      // 3. Generate attestation
      const attestation = generateAttestation(web3, message);
      console.log(`Attestation hex: 0x${Buffer.from(attestation).toString("hex")}`);

      // 4. Execute receive_message
      try {
        await stablecoinHandlerClient.receiveMessage(
          cctpPackagesFilePath,
          deployer,
          MoveVector.U8(message),
          MoveVector.U8(attestation)
        );

        // If the receiveMessage tx succeeds, fail the test
        fail("Receive message tx should have failed with EEXPIRED_MESSAGE");
      } catch (error) {
        // Verify it failed with EEXPIRED_MESSAGE
        expect(error.message).toContain("token_messenger_minter: EEXPIRED_MESSAGE");
      }
    });
  });
});
