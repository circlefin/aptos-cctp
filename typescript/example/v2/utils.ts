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

import Web3 from "web3";

export const APTOS_DOMAIN = 9;
export const DEFAULT_EVM_DESTINATION_DOMAIN = 6; // Base Sepolia

export const FINALITY_THRESHOLD_FINALIZED = 2000;
export const FINALITY_THRESHOLD_CONFIRMED = 1000;

const IRIS_API_URL = process.env.IRIS_API_URL || "https://iris-api-sandbox.circle.com";
const ATTESTATION_POLL_INTERVAL_MS = 2_000;
const MAX_ATTESTATION_POLL_ATTEMPTS = 90;
const RECEIPT_POLL_INTERVAL_MS = 4_000;
const MAX_RECEIPT_POLL_ATTEMPTS = 60;

export function getRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

// Polls GET /v2/messages/{sourceDomain}?transactionHash={txHash}
// Returns the message bytes and attestation once available.
export async function fetchAttestation(
  sourceDomain: number,
  txHash: string
): Promise<{ message: string; attestation: string }> {
  const url = `${IRIS_API_URL}/v2/messages/${sourceDomain}?transactionHash=${txHash}`;
  console.log(`Polling Iris V2 API for attestation: ${url}`);

  for (let attempt = 0; attempt < MAX_ATTESTATION_POLL_ATTEMPTS; attempt += 1) {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(
        `Iris V2 API request failed with ${response.status} ${response.statusText}`,
      );
    }

    const data = await response.json();
    const message = data.messages?.[0];
    if (message?.attestation && message.attestation !== "PENDING") {
      console.log("Attestation received from Iris V2 API.");
      return {
        message: message.message,
        attestation: message.attestation,
      };
    }

    await new Promise((resolve) => setTimeout(resolve, ATTESTATION_POLL_INTERVAL_MS));
  }

  throw new Error(
    `Attestation was not available after ${MAX_ATTESTATION_POLL_ATTEMPTS} attempts`,
  );
}

// Polls getTransactionReceipt until the transaction is mined, then asserts success.
export async function waitForEvmTransaction(web3: Web3, txHash: string) {
  let receipt = await web3.eth.getTransactionReceipt(txHash);
  for (
    let attempt = 1;
    receipt == null && attempt <= MAX_RECEIPT_POLL_ATTEMPTS;
    attempt += 1
  ) {
    await new Promise((resolve) => setTimeout(resolve, RECEIPT_POLL_INTERVAL_MS));
    receipt = await web3.eth.getTransactionReceipt(txHash);
  }
  if (receipt == null) {
    throw new Error(
      `Transaction receipt was not available after ${MAX_RECEIPT_POLL_ATTEMPTS} attempts: ${txHash}`,
    );
  }
  if (receipt.status !== BigInt(1)) {
    throw new Error(`Transaction reverted: ${txHash}`);
  }
  return receipt;
}
