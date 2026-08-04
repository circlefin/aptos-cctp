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

import {
  Account,
  AccountAddress,
  Aptos,
  AptosConfig,
  Ed25519PrivateKey,
  Network,
  U32,
  U64,
} from "@aptos-labs/ts-sdk";
import { readFileSync } from "fs";
import Web3 from "web3";
import {
  APTOS_DOMAIN,
  DEFAULT_EVM_DESTINATION_DOMAIN,
  FINALITY_THRESHOLD_FINALIZED,
  fetchAttestation,
  getRequiredEnv,
  waitForEvmTransaction,
} from "./utils";

const EVM_PRIVATE_KEY = getRequiredEnv("EVM_PRIVATE_KEY");
const APTOS_PRIVATE_KEY = getRequiredEnv("APTOS_PRIVATE_KEY");
const EVM_RPC_URL = getRequiredEnv("EVM_RPC_URL");
const EVM_MESSAGE_TRANSMITTER_V2_ADDRESS = getRequiredEnv("EVM_MESSAGE_TRANSMITTER_V2_ADDRESS");
const APTOS_BURN_TOKEN = getRequiredEnv("APTOS_BURN_TOKEN");
const EVM_DESTINATION_DOMAIN = Number(process.env.EVM_DESTINATION_DOMAIN || DEFAULT_EVM_DESTINATION_DOMAIN);

// Example: Transfer 1 USDC from Aptos to EVM (finalized, regular transfer)
const main = async () => {
  const web3 = new Web3(EVM_RPC_URL);
  const evmSigner = web3.eth.accounts.privateKeyToAccount(EVM_PRIVATE_KEY);
  web3.eth.accounts.wallet.add(evmSigner);

  const aptosClient = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const userAccount = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(APTOS_PRIVATE_KEY) });

  // STEP 1: Build and submit deposit-for-burn transaction on Aptos
  const bytecode = Uint8Array.from(
    readFileSync("typescript/example/precompiled-move-scripts/testnet/v2/deposit_for_burn.mv")
  );
  const functionArguments: Array<any> = [
    new U64(1_000_000),                            // amount (1 USDC)
    new U32(EVM_DESTINATION_DOMAIN),               // destinationDomain
    AccountAddress.from(evmSigner.address),        // mintRecipient
    AccountAddress.from("0x0"),                    // destinationCaller (anyone can relay)
    AccountAddress.from(APTOS_BURN_TOKEN),         // burnToken
    new U64(0),                                    // maxFee = 0: accept no fee deduction from transferred amount
    new U32(FINALITY_THRESHOLD_FINALIZED),         // minFinalityThreshold
  ];
  const transaction = await aptosClient.transaction.build.simple({
    sender: userAccount.accountAddress,
    data: { bytecode, functionArguments },
  });
  const pendingTxn = await aptosClient.signAndSubmitTransaction({ signer: userAccount, transaction });
  const depositForBurnTx = await aptosClient.waitForTransaction({ transactionHash: pendingTxn.hash });
  console.log(`Deposit for burn tx: https://explorer.aptoslabs.com/txn/${depositForBurnTx.hash}`);

  // STEP 2: Poll Iris V2 for attestation
  const { message, attestation } = await fetchAttestation(APTOS_DOMAIN, depositForBurnTx.hash);

  // STEP 3: Receive message on EVM
  const messageTransmitterAbi = JSON.parse(
    readFileSync("typescript/example/v2/abi/MessageTransmitterV2.json").toString()
  );
  const messageTransmitterContract = new web3.eth.Contract(
    messageTransmitterAbi.abi,
    EVM_MESSAGE_TRANSMITTER_V2_ADDRESS,
    { from: evmSigner.address }
  );
  const receiveTxGas = await messageTransmitterContract.methods
    .receiveMessage(message, attestation)
    .estimateGas();
  const receiveTx = await messageTransmitterContract.methods
    .receiveMessage(message, attestation)
    .send({ gas: receiveTxGas.toString() });

  console.log(`Waiting for EVM receive tx: https://sepolia.basescan.org/tx/${receiveTx.transactionHash}`);
  const receipt = await waitForEvmTransaction(web3, receiveTx.transactionHash);
  console.log(`Receive tx confirmed: https://sepolia.basescan.org/tx/${receipt.transactionHash}`);
};

main();
