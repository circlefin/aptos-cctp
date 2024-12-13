/**
 * Copyright (c) 2024, Circle Internet Group, Inc. All rights reserved.
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
  UserTransactionResponse,
} from "@aptos-labs/ts-sdk";
import { readFileSync } from "fs";
import Web3 from "web3";

// Aptos Testnet Message Transmitter
const MESSAGE_TRANSMITTER_PACKAGE_ID = "0x81e86cebf457a0c6004f35bd648a2794698f52e0dde09a48619dcd3d4cc23d9";
// Aptos Testnet Stablecoin object
const BURN_TOKEN = "0x69091fbab5f7d635ee7ac5098cf0c1efbe31d68fec0f2cd565e8d168daf52832";
// Base Testnet Message Transmitter
const EVM_MESSAGE_TRANSMITTER_ADDRESS = "0x7865fAfC2db2093669d92c0F33AeEF291086BEFD";
const EVM_PRIVATE_KEY = process.env.EVM_PRIVATE_KEY;
const APTOS_PRIVATE_KEY = process.env.APTOS_PRIVATE_KEY;
const EVM_RPC_URL = process.env.EVM_RPC_URL;

// Example script for transferring 1 USDC from APTOS to BASE
const main = async () => {
  const web3 = new Web3(EVM_RPC_URL);
  const evmSigner = web3.eth.accounts.privateKeyToAccount(EVM_PRIVATE_KEY);
  web3.eth.accounts.wallet.add(evmSigner);

  const aptosClient = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const userAccount = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(APTOS_PRIVATE_KEY) });

  // Create a transaction with deposit for burn script
  const buffer = readFileSync("typescript/example/precompiled-move-scripts/testnet/deposit_for_burn.mv");
  const bytecode = Uint8Array.from(buffer);
  const amount = new U64(1);
  const destinationDomain = new U32(6);
  const burnToken = AccountAddress.from(BURN_TOKEN);
  const mintRecipient = AccountAddress.from(evmSigner.address);
  const functionArguments: Array<any> = [amount, destinationDomain, mintRecipient, burnToken];
  const transaction = await aptosClient.transaction.build.simple({
    sender: userAccount.accountAddress,
    data: {
      bytecode,
      functionArguments,
    },
  });
  const pendingTxn = await aptosClient.signAndSubmitTransaction({
    signer: userAccount,
    transaction,
  });
  const depositForBurnTx = await aptosClient.waitForTransaction({ transactionHash: pendingTxn.hash });
  console.log(
    `Deposit for burn transaction completed successfully: https://explorer.aptoslabs.com/txn/${depositForBurnTx.hash}`
  );

  // Fetch the event data from the transaction
  const messageSentEvent = (depositForBurnTx as UserTransactionResponse).events.find(
    (e: any) => e.type === `${MESSAGE_TRANSMITTER_PACKAGE_ID}::message_transmitter::MessageSent`
  );

  // Wait for attestation
  const messageBytes = messageSentEvent.data.message;
  const messageHash = web3.utils.keccak256(messageBytes);
  let attestationResponse = { status: "pending", attestation: "" };
  console.log(`Waiting for attestation: https://iris-api-sandbox.circle.com/attestations/${messageHash}`);
  while (attestationResponse.status != "complete") {
    const response = await fetch(`https://iris-api-sandbox.circle.com/attestations/${messageHash}`);
    attestationResponse = await response.json();
    await new Promise((r) => setTimeout(r, 5_000));
  }
  console.log(`Message attested: https://iris-api-sandbox.circle.com/attestations/${messageHash}`);

  // Use the attestation and message data to receive the message on the EVM
  const attestationSignature = attestationResponse.attestation;
  const messageTransmitterInterface = JSON.parse(
    readFileSync("typescript/example/abi/MessageTransmitter.json").toString()
  );
  const evmMessageTransmitterContract = new web3.eth.Contract(
    messageTransmitterInterface.abi,
    EVM_MESSAGE_TRANSMITTER_ADDRESS,
    {
      from: evmSigner.address,
    }
  );
  const receiveTxGas = await evmMessageTransmitterContract.methods
    .receiveMessage(messageBytes, attestationSignature)
    .estimateGas();
  const receiveTx = await evmMessageTransmitterContract.methods
    .receiveMessage(messageBytes, attestationSignature)
    .send({ gas: receiveTxGas.toString() });

  console.log(`Wait for ReceiveTx to complete: https://sepolia.basescan.org/tx/${receiveTx.transactionHash}`);
  let receiveTxReceipt = { transactionHash: receiveTx.transactionHash, status: BigInt(0) };
  while (receiveTxReceipt != null && receiveTxReceipt.status != BigInt(1)) {
    receiveTxReceipt = await web3.eth.getTransactionReceipt(receiveTx.transactionHash);
    await new Promise((r) => setTimeout(r, 4_000));
  }
  console.log(`ReceiveTxReceipt: https://sepolia.basescan.org/tx/${receiveTxReceipt.transactionHash}`);
};

main();
