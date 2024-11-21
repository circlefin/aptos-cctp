/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Copyright (c) 2024, Circle Internet Group, Inc.
 * All rights reserved.
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
import { expect } from "@jest/globals";
import * as ethutil from "@ethereumjs/util";
import waitForExpect from "wait-for-expect";
import { Contract, EventLog, TransactionReceipt, Web3 } from "web3";

export interface EvmContractDefinition {
  messageTransmitterContract: Contract<any>;
  messageTransmitterContractAddress: string;
  tokenMessengerContract: Contract<any>;
  tokenMessengerContractAddress: string;
  tokenMinterContract: Contract<any>;
  tokenMinterContractAddress: string;
  usdcContract: Contract<any>;
  usdcContractAddress: string;
  web3: Web3;
}

export const attestedMessage = async (
  contractDefinition: EvmContractDefinition,
  txReceipt: TransactionReceipt
): Promise<{ attestation: string; txHash: string; messageBytes: Buffer; blockHeight: number }> => {
  // Create an attestation using the initialized Anvil keypair
  let logs: any = [];
  await waitForExpect(async () => {
    logs = await contractDefinition.messageTransmitterContract.getPastEvents("MessageSent", {
      fromBlock: txReceipt.blockNumber,
      toBlock: txReceipt.blockNumber,
    });
    expect(logs.length).toBeGreaterThan(0);
  }, 90_000);

  const messageBytes = String((logs[0] as EventLog).returnValues.message);

  return {
    attestation: attestToMessage(contractDefinition.web3, messageBytes),
    messageBytes: Buffer.from(messageBytes.replace("0x", ""), "hex"),
    txHash: String(txReceipt.transactionHash),
    blockHeight: Number(txReceipt.blockNumber),
  };
};

export const attestToMessage = (web3: Web3, messageBytes: string): string => {
  // Create an attestation using the initialized Anvil keypair
  const attesterPrivateKey = "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";

  const messageHash = web3.utils.keccak256(messageBytes);
  const signedMessage = ethutil.ecsign(
    Buffer.from(ethutil.toBytes(messageHash)),
    Buffer.from(ethutil.toBytes(attesterPrivateKey))
  );
  const attestation = ethutil.toRpcSig(signedMessage.v, signedMessage.r, signedMessage.s);
  return attestation;
};

// Generates a depositForBurn tx from the given evm chain
export const generateEvmBurn = async (
  contractDefinition: EvmContractDefinition,
  userAddress: string,
  destAddress: string,
  destDomain: number
): Promise<{ attestation: string; txHash: string; messageBytes: Buffer; blockHeight: number }> => {
  // Set allowance for the userAddress
  const txReceipt1 = await contractDefinition.usdcContract.methods
    .approve(contractDefinition.tokenMessengerContractAddress, 1000)
    .send({ from: userAddress });
  expect(txReceipt1.status).toBe(BigInt(1));

  const paddedDestAddress = contractDefinition.web3.utils.padLeft(destAddress, 64);

  // Initiate a depositForBurn from the userAddress
  const txReceipt2: TransactionReceipt = await contractDefinition.tokenMessengerContract.methods
    .depositForBurn(1, destDomain, paddedDestAddress, contractDefinition.usdcContractAddress)
    .send({ from: userAddress });
  expect(txReceipt2.status).toBe(BigInt(1));

  return attestedMessage(contractDefinition, txReceipt2);
};

// Generates a sendMessage tx from the given evm chain
export const generateEvmSendMessage = async (
  contractDefinition: EvmContractDefinition,
  userAddress: string,
  destAddress: string,
  destDomain: number
): Promise<{ attestation: string; txHash: string; messageBytes: Buffer; blockHeight: number }> => {
  const paddedDestAddress = contractDefinition.web3.utils.padLeft(destAddress, 64);
  const txReceipt: TransactionReceipt = await contractDefinition.messageTransmitterContract.methods
    .sendMessage(destDomain, paddedDestAddress, "0x6d657373616765") // "message" string hex encoded
    .send({ from: userAddress });
  expect(txReceipt.status).toBe(BigInt(1));
  return attestedMessage(contractDefinition, txReceipt);
};

export const receiveEvm = async (
  evmTestAddress: string,
  destination: EvmContractDefinition,
  message: Buffer,
  attestation: string
): Promise<void> => {
  const destinationFrom = await destination.web3.eth.getBlockNumber();
  const destinationTxReceipt: TransactionReceipt = await destination.messageTransmitterContract.methods
    .receiveMessage(message, attestation)
    .send({ from: evmTestAddress });

  const destinationLogs = await destination.messageTransmitterContract.getPastEvents("MessageReceived", {
    fromBlock: destinationFrom,
    toBlock: BigInt(destinationTxReceipt.blockNumber) + BigInt(1),
  });
  expect(destinationLogs.length).toBeGreaterThan(0);
};
