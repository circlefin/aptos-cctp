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
  Aptos,
  AptosConfig,
  Ed25519PrivateKey,
  MoveVector,
  Network,
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
const EVM_TOKEN_MESSENGER_V2_ADDRESS = getRequiredEnv("EVM_TOKEN_MESSENGER_V2_ADDRESS");
const EVM_USDC_ADDRESS = getRequiredEnv("EVM_USDC_ADDRESS");
const EVM_SOURCE_DOMAIN = Number(process.env.EVM_SOURCE_DOMAIN || DEFAULT_EVM_DESTINATION_DOMAIN);
const USDC_AMOUNT = 1_000_000; // 1 USDC (6 decimal places)

// Example: Transfer 1 USDC from EVM to Aptos (finalized, regular transfer)
const main = async () => {
  const web3 = new Web3(EVM_RPC_URL);
  const evmSigner = web3.eth.accounts.privateKeyToAccount(EVM_PRIVATE_KEY);
  web3.eth.accounts.wallet.add(evmSigner);

  const aptosClient = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const userAccount = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(APTOS_PRIVATE_KEY) });

  const tokenMessengerAbi = JSON.parse(
    readFileSync("typescript/example/v2/abi/TokenMessengerV2.json").toString()
  );
  const usdcAbi = JSON.parse(
    readFileSync("typescript/example/v2/abi/FiatTokenV2_1.json").toString()
  );
  const tokenMessengerContract = new web3.eth.Contract(
    tokenMessengerAbi.abi,
    EVM_TOKEN_MESSENGER_V2_ADDRESS,
    { from: evmSigner.address }
  );
  const usdcContract = new web3.eth.Contract(
    usdcAbi.abi,
    EVM_USDC_ADDRESS,
    { from: evmSigner.address }
  );

  // STEP 1: Approve TokenMessengerV2 to spend USDC
  const approveTxGas = await usdcContract.methods
    .approve(EVM_TOKEN_MESSENGER_V2_ADDRESS, USDC_AMOUNT)
    .estimateGas();
  const approveTx = await usdcContract.methods
    .approve(EVM_TOKEN_MESSENGER_V2_ADDRESS, USDC_AMOUNT)
    .send({ gas: approveTxGas.toString() });
  const approveReceipt = await waitForEvmTransaction(web3, approveTx.transactionHash);
  console.log(`Approve tx: https://sepolia.basescan.org/tx/${approveReceipt.transactionHash}`);

  // STEP 2: Burn USDC on EVM via depositForBurn
  const mintRecipient = userAccount.accountAddress.toString();
  const destinationCaller = "0x0000000000000000000000000000000000000000000000000000000000000000";
  const burnTxGas = await tokenMessengerContract.methods
    .depositForBurn(USDC_AMOUNT, APTOS_DOMAIN, mintRecipient, EVM_USDC_ADDRESS, destinationCaller, 0, FINALITY_THRESHOLD_FINALIZED)
    .estimateGas();
  const burnTx = await tokenMessengerContract.methods
    .depositForBurn(USDC_AMOUNT, APTOS_DOMAIN, mintRecipient, EVM_USDC_ADDRESS, destinationCaller, 0, FINALITY_THRESHOLD_FINALIZED)
    .send({ gas: burnTxGas.toString() });
  const burnReceipt = await waitForEvmTransaction(web3, burnTx.transactionHash);
  console.log(`Deposit for burn tx: https://sepolia.basescan.org/tx/${burnReceipt.transactionHash}`);

  // STEP 3: Poll Iris V2 for attestation
  const { message, attestation } = await fetchAttestation(EVM_SOURCE_DOMAIN, burnTx.transactionHash);

  // STEP 4: Receive message on Aptos
  const bytecode = Uint8Array.from(
    readFileSync("typescript/example/precompiled-move-scripts/testnet/v2/receive_message.mv")
  );
  const functionArguments: Array<any> = [
    MoveVector.U8(Buffer.from(message.replace("0x", ""), "hex")),
    MoveVector.U8(Buffer.from(attestation.replace("0x", ""), "hex")),
  ];
  const transaction = await aptosClient.transaction.build.simple({
    sender: userAccount.accountAddress,
    data: { bytecode, functionArguments },
  });
  const pendingTxn = await aptosClient.signAndSubmitTransaction({ signer: userAccount, transaction });
  const receiveMessageTx = await aptosClient.waitForTransaction({ transactionHash: pendingTxn.hash });
  console.log(`Receive message tx: https://explorer.aptoslabs.com/txn/${receiveMessageTx.hash}`);
};

main();
