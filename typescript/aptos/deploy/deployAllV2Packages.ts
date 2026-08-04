/**
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.
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

import { program } from "commander";
import { Ed25519Account, Ed25519PrivateKey } from "@aptos-labs/ts-sdk";
import { MessageTransmitterClientV2 } from "../client/messageTransmitterClientV2";
import { getAptosClient } from "../utils/helper";
import { TokenMessengerMinterClientV2 } from "../client/tokenMessengerMinterClientV2";
import { CctpExtensionsClient } from "../client/cctpExtensionsClient";
import { StablecoinHandlerClient } from "../client/stablecoinHandlerClient";

export type DeployAllV2PackagesOptions = {
  privateKey: string;
  rpc: string;
  aptosExtensionsPackageId: string;
  stablecoinPackageId: string;
  includedArtifacts: string;
};

async function deployAllV2Packages(options: DeployAllV2PackagesOptions) {
  const aptos = getAptosClient(options.rpc);
  const deployer = new Ed25519Account({
    privateKey: new Ed25519PrivateKey(options.privateKey),
  });
  console.log(`Deployer account: ${deployer.accountAddress}\n`);

  const cctpExtensionsClient = new CctpExtensionsClient(aptos, deployer);
  const messageTransmitterClient = new MessageTransmitterClientV2(aptos, deployer);
  const tokenMessengerMinterClient = new TokenMessengerMinterClientV2(aptos, deployer);
  const stablecoinHandlerClient = new StablecoinHandlerClient(aptos, deployer);

  // Deploy CctpExtensions
  const cctpExtensionsPackageId = await cctpExtensionsClient.publishPackage(
    "packages",
    options.aptosExtensionsPackageId,
    options.includedArtifacts
  );
  console.log(`CctpExtensions package ID: ${cctpExtensionsPackageId}\n`);

  // Deploy MessageTransmitterV2
  const messageTransmitterPackageId = await messageTransmitterClient.publishPackage(
    "packages",
    options.aptosExtensionsPackageId,
    cctpExtensionsPackageId,
    options.includedArtifacts
  );
  console.log(`MessageTransmitterV2 package ID: ${messageTransmitterPackageId}\n`);

  // Deploy TokenMessengerMinterV2
  const tokenMessengerMinterPackageId = await tokenMessengerMinterClient.publishPackage(
    "packages",
    options.aptosExtensionsPackageId,
    messageTransmitterPackageId,
    cctpExtensionsPackageId,
    options.includedArtifacts
  );
  console.log(`TokenMessengerMinterV2 package ID: ${tokenMessengerMinterPackageId}\n`);

  // Deploy StablecoinHandler
  const stablecoinHandlerPackageId = await stablecoinHandlerClient.publishPackage(
    "packages",
    options.aptosExtensionsPackageId,
    options.stablecoinPackageId,
    cctpExtensionsPackageId,
    messageTransmitterPackageId,
    tokenMessengerMinterPackageId,
    options.includedArtifacts
  );
  console.log(`StablecoinHandler package ID: ${stablecoinHandlerPackageId}\n`);

  // Summary
  console.log("=== Deployment Summary ===");
  console.log(`Deployer:                ${deployer.accountAddress}`);
  console.log(`CctpExtensions:          ${cctpExtensionsPackageId}`);
  console.log(`MessageTransmitterV2:    ${messageTransmitterPackageId}`);
  console.log(`TokenMessengerMinterV2:  ${tokenMessengerMinterPackageId}`);
  console.log(`StablecoinHandler:       ${stablecoinHandlerPackageId}`);
}

/*
Example - yarn deploy-v2 --privateKey=<privateKey> --rpc=http://localhost:8080 \
  --aptosExtensionsPackageId=0x... --stablecoinPackageId=0x...
*/

export default program
  .createCommand("deploy-v2")
  .description("Deploy all V2 packages")
  .requiredOption("--privateKey <string>", "Deployer private key")
  .requiredOption("--rpc <string>", "RPC URL")
  .requiredOption("--aptosExtensionsPackageId <string>", "AptosExtensions package address")
  .requiredOption("--stablecoinPackageId <string>", "Stablecoin package address")
  .option("--includedArtifacts <string>", "Included artifacts", "none")
  .action(deployAllV2Packages);
