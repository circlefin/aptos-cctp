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

import { Web3 } from "web3";
import fs from "fs";
import {
  Account,
  Aptos,
  AptosConfig,
  Ed25519PrivateKey,
  Network,
  MoveVector
} from "@aptos-labs/ts-sdk";

const USDC_AMOUNT = 1;
const APTOS_DOMAIN = 9;

const EVM_TOKEN_MESSENGER_CONTRACT_ADDRESS = "0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5"; // Base testnet
const USDC_ETH_CONTRACT_ADDRESS = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const EVM_PRIVATE_KEY = process.env.EVM_PRIVATE_KEY;
const APTOS_PRIVATE_KEY = process.env.APTOS_PRIVATE_KEY;
const EVM_RPC_URL = process.env.EVM_RPC_URL;

const waitForTransaction = async(web3: Web3, txHash: string) => {
  let transactionReceipt = await web3.eth.getTransactionReceipt(txHash);
  while(transactionReceipt != null && transactionReceipt.status === BigInt(0)) {
    transactionReceipt = await web3.eth.getTransactionReceipt(txHash);
    await new Promise(r => setTimeout(r, 4000));
  }
  return transactionReceipt;
};


/**
 * // Example script for transferring 1 USDC from BASE to APTOS
 */
const main = async () => {
  // EVM setup
  const web3 = new Web3(new Web3.providers.HttpProvider(EVM_RPC_URL));
  const evmSigner = web3.eth.accounts.privateKeyToAccount(EVM_PRIVATE_KEY);
  web3.eth.accounts.wallet.add(evmSigner);

  // Aptos setup
  const aptosClient = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const userAccount = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(APTOS_PRIVATE_KEY) });

  // initialize contracts using address and ABI
  const tokenMessengerInterface = JSON.parse(
    fs.readFileSync("typescript/example/abi/TokenMessenger.json").toString()
  );
  const usdcInterface = JSON.parse(fs.readFileSync("typescript/example/abi/FiatTokenV2_1.json").toString());

  const evmTokenMessengerContract = new web3.eth.Contract(
    tokenMessengerInterface.abi,
    EVM_TOKEN_MESSENGER_CONTRACT_ADDRESS,
    { from: evmSigner.address }
  );
  const usdcEthContract = new web3.eth.Contract(usdcInterface.abi, USDC_ETH_CONTRACT_ADDRESS,  { from: evmSigner.address });

  // STEP 1: Approve messenger contract to withdraw from our active eth address
  const approveTxGas = await usdcEthContract.methods.approve(EVM_TOKEN_MESSENGER_CONTRACT_ADDRESS, USDC_AMOUNT).estimateGas();
  const approveTx = await usdcEthContract.methods.approve(EVM_TOKEN_MESSENGER_CONTRACT_ADDRESS, USDC_AMOUNT).send({ gas: approveTxGas.toString() });
  const approveTxReceipt = await waitForTransaction(web3, approveTx.transactionHash);
  console.log(`ApproveTxReceipt: https://sepolia.basescan.org/tx/${approveTxReceipt.transactionHash}`);

  // STEP 2: Burn USDC on EVM
  const burnTxGas = await evmTokenMessengerContract.methods.depositForBurn(USDC_AMOUNT, APTOS_DOMAIN, userAccount.accountAddress.toString(), USDC_ETH_CONTRACT_ADDRESS).estimateGas();
  const burnTx = await evmTokenMessengerContract.methods.depositForBurn(USDC_AMOUNT, APTOS_DOMAIN, userAccount.accountAddress.toString(), USDC_ETH_CONTRACT_ADDRESS).send({gas: burnTxGas.toString()});
  const burnTxReceipt = await waitForTransaction(web3, burnTx.transactionHash);
  console.log(`DepositForBurnTxReceipt: https://sepolia.basescan.org/tx/${burnTxReceipt.transactionHash}`);

  // STEP 3: Retrieve message bytes from logs
  const transactionReceipt = await web3.eth.getTransactionReceipt(burnTx.transactionHash);
  const eventTopic = web3.utils.keccak256('MessageSent(bytes)')
  const log = transactionReceipt.logs.find((l) => l.topics[0] === eventTopic)
  const messageBytes = web3.eth.abi.decodeParameters(['bytes'], log.data)[0]
  const messageHash = web3.utils.keccak256(messageBytes as string);

  // STEP 4: Fetch attestation signature
  let attestationResponse = {status: 'pending', attestation: ''};
  while(attestationResponse.status !== 'complete') {
    const response = await fetch(`https://iris-api-sandbox.circle.com/attestations/${messageHash}`);
    attestationResponse = await response.json()
    await new Promise(r => setTimeout(r, 2000));
  }
  console.log(`Message attested: https://iris-api-sandbox.circle.com/attestations/${messageHash}`);

  const attestationSignature = attestationResponse.attestation;

  // STEP 5: Use message bytes and signature to receive the usdc on Aptos
  const bytecode = Uint8Array.from(fs.readFileSync("typescript/example/precompiled-move-scripts/testnet/handle_receive_message.mv"));
  const functionArguments: Array<any> = [MoveVector.U8(messageBytes as Buffer), MoveVector.U8(attestationSignature)];
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
  const receiveMessageTx = await aptosClient.waitForTransaction({ transactionHash: pendingTxn.hash });
  console.log(
    `Receive message transaction completed successfully: https://explorer.aptoslabs.com/txn/${receiveMessageTx.hash}`
  );
};
main();
