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

import { program } from "commander";
import { Ed25519Account, Ed25519PrivateKey } from "@aptos-labs/ts-sdk";
import { MessageTransmitterClient } from "../client/messageTransmitterClient";
import { getAptosClient } from "../utils/helper";
import { TokenMessengerMinterClient } from "../client/tokenMessengerMinterClient";

export type DeployAllPackagesOptions = {
  privateKey: string;
  rpc: string;
  aptosExtensionsPackageId: string;
  stablecoinPackageId: string;
  includedArtifacts: string;
};

async function deployAllPackages(options: DeployAllPackagesOptions) {
  const aptos = getAptosClient(options.rpc);
  const deployer = new Ed25519Account({
    privateKey: new Ed25519PrivateKey(options.privateKey),
  });
  console.log(`Deployer account: ${deployer.accountAddress}\n`);

  const messageTransmitterClient = new MessageTransmitterClient(aptos, deployer);
  const tokenMessengerMinterClient = new TokenMessengerMinterClient(aptos, deployer);

  const messageTransmitterPackageId = await messageTransmitterClient.publishPackage(
    "packages",
    options.aptosExtensionsPackageId,
    options.includedArtifacts
  );
  console.log(`MessageTransmitter package ID: ${messageTransmitterPackageId}\n`);

  const tokenMessengerMinterPackageId = await tokenMessengerMinterClient.publishPackage(
    "packages",
    options.aptosExtensionsPackageId,
    messageTransmitterPackageId,
    options.stablecoinPackageId,
    options.includedArtifacts
  );
  console.log(`TokenMessengerMinter package ID: ${tokenMessengerMinterPackageId}\n`);
}

/*
Example - yarn deploy --privateKey=<privateKey> --rpc=http://localhost:8080 --aptosExtensionsPackageId=0x9b43208bdff59a953f929309b1238ad0126a471002796261f8ce936c59917efb --stablecoinPackageId=0xf8e95ec344bb3fa74d2539fe15a01094ab3746ed3782c740e8befdd37e8095c7
*/

export default program
  .createCommand("deploy")
  .description("Deploy all packages")
  .requiredOption("--privateKey <string>", "Deployer Private key")
  .requiredOption("--rpc <string>", "RPC URL")
  .requiredOption("--aptosExtensionsPackageId <string>", "AptosExtensions package address")
  .requiredOption("--stablecoinPackageId <string>", "Stablecoin package address")
  .option("--includedArtifacts <string>", "Included artifacts", "none")
  .action(deployAllPackages);
