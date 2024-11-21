/**
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  Aptos,
  Account,
  Ed25519Account,
  Event,
  UserTransactionResponse,
  InputGenerateTransactionPayloadData,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
  MoveModuleBytecode,
} from "@aptos-labs/ts-sdk";
import { execSync } from "child_process";

import fs from "fs";

export type NamedAddress = { name: string; address: string };

export function getAptosClient(url?: string): Aptos {
  return url === undefined
    ? new Aptos(new AptosConfig({ network: Network.LOCAL }))
    : new Aptos(
        new AptosConfig({
          fullnode: `${url}/v1`,
        })
      );
}

/**
 * @returns a new account with 1_000_000_000 Aptos
 */
export async function generateFundedAccount(aptosClient: Aptos): Promise<Ed25519Account> {
  const acct = Account.generate();
  await aptosClient.fundAccount({
    accountAddress: acct.accountAddress,
    amount: 1_000_000_000,
  });
  return acct;
}

/**
 * @returns a new account with 1_000_000_000 Aptos
 */
export async function generateFundedAccountFromPrivateKey(
  aptosClient: Aptos,
  privateKey: string
): Promise<Ed25519Account> {
  const acct = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(privateKey) });
  await aptosClient.fundAccount({
    accountAddress: acct.accountAddress,
    amount: 1_000_000_000,
  });
  return acct;
}

/**
 * Finds a specific event from the transaction output
 */
export function getEventByType(txOutput: UserTransactionResponse, eventType: string): Event {
  const event = txOutput.events.find((e: any) => e.type === eventType);
  return event;
}

/**
 * Reformat address to ensure it is 0x-prefixed and 66 characters long
 */
export function normalizeAddress(address: string): string {
  if (address.length < 66) {
    return `0x${address.replace("0x", "").padStart(64, "0")}`;
  }
  return address;
}

/**
 * Executes a transaction and waits for it to be included in a block
 * @returns the transaction output
 * @throws if the transaction fails
 */
export async function executeTransaction({
  aptos,
  sender,
  data,
}: {
  aptos: Aptos;
  sender: Ed25519Account;
  data: InputGenerateTransactionPayloadData;
}): Promise<UserTransactionResponse> {
  const transaction = await aptos.transaction.build.simple({
    sender: sender.accountAddress,
    data,
  });
  const response = await aptos.signAndSubmitTransaction({
    signer: sender,
    transaction,
  });
  const txOutput = await aptos.waitForTransaction({
    transactionHash: response.hash,
  });
  if (!txOutput.success) {
    console.error(txOutput);
    throw new Error("Unexpected transaction failure");
  }
  return txOutput as UserTransactionResponse;
}

/**
 * Parses the package address from the transaction output
 */
export function getPublishedPackageFromTxOutput(txOutput: UserTransactionResponse): string {
  const rawCodeAddress = getEventByType(txOutput, "0x1::code::PublishPackage").data.code_address;
  return normalizeAddress(rawCodeAddress);
}

export async function buildPackage(
  packageDir: string,
  packageName: string,
  namedAddresses: NamedAddress[],
  includedArtifacts: string
): Promise<{
  metadataBytes: string;
  bytecode: string[];
}> {
  const payloadFilePath = await buildPackagePublishPayload(packageDir, packageName, namedAddresses, includedArtifacts);
  const jsonData = JSON.parse(fs.readFileSync(payloadFilePath, "utf-8"));
  fs.unlinkSync(payloadFilePath); // delete saved json at PAYLOAD_FILE_PATH

  return {
    metadataBytes: jsonData.args[0].value,
    bytecode: jsonData.args[1].value,
  };
}

/**
 * A convenience function to compile a package locally with the CLI
 * @param packageDir
 * @param packageName
 * @param namedAddresses
 */
export async function buildPackagePublishPayload(
  packageDir: string,
  packageName: string,
  namedAddresses: NamedAddress[],
  includedArtifacts: string
) {
  const addressArg = formatNamedAddresses(namedAddresses);
  const payloadFilePath = `build-output-${packageName}-${Date.now()}.json`;
  const buildCommand = `aptos move build-publish-payload --json-output-file ${payloadFilePath} --package-dir ${packageDir} --named-addresses ${addressArg} --included-artifacts ${includedArtifacts}`;
  execSync(buildCommand, { encoding: "utf-8" });
  if (!fs.existsSync(payloadFilePath)) {
    throw new Error(`Build failed with the following command: ${buildCommand}`);
  }
  return payloadFilePath;
}

/**
 * Fetches the bytecode of a package
 * Works for packages that have up to 25 modules
 * @returns string[] of bytecode
 */
export async function getPackageBytecode(aptos: Aptos, packageId: string): Promise<string[]> {
  const rawRemoteModuleBytecode: MoveModuleBytecode[] = await aptos.getAccountModules({
    accountAddress: packageId,
    options: { limit: 25 },
  });
  return rawRemoteModuleBytecode.map((module) => module.bytecode);
}

/**
 * Formats a list of named addresses into a string of the format "name1=address1,name2=address2"
 */
export function formatNamedAddresses(namedAddresses: NamedAddress[]): string {
  return namedAddresses.map(({ name, address }) => `${name}=${address}`).join(",");
}

/**
 * Parses a string of named addresses in the format "name1=address1,name2=address2"
 */
export function parseNamedAddresses(namedAddressArg: string): NamedAddress[] {
  return namedAddressArg.split(",").map((arg) => {
    const [name, address] = arg.split("=");
    return { name, address };
  });
}
