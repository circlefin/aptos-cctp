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
import { verifyPackage } from "./verifyPackage";
import { PackageName } from "../utils/package";

export type VerifyAllV2PackagesOptions = {
  deployer: string;
  rpc: string;
  aptosExtensionsPackageId: string;
  stablecoinPackageId: string;
  cctpExtensionsPackageId: string;
  messageTransmitterV2PackageId: string;
  tokenMessengerMinterV2PackageId: string;
  stablecoinHandlerPackageId: string;
  includedArtifacts: string;
};

async function verifyAllV2Packages(options: VerifyAllV2PackagesOptions) {
  const results = [];

  // Verify CctpExtensions
  console.log("Verifying CctpExtensions...\n");
  results.push(
    await verifyPackage({
      packageName: PackageName.CctpExtensions,
      packageId: options.cctpExtensionsPackageId,
      namedDeps: [
        { name: "deployer", address: options.deployer },
        { name: PackageName.AptosExtensions, address: options.aptosExtensionsPackageId },
      ],
      rpc: options.rpc,
      includedArtifacts: options.includedArtifacts,
    })
  );

  // Verify MessageTransmitterV2
  console.log("Verifying MessageTransmitterV2...\n");
  results.push(
    await verifyPackage({
      packageName: PackageName.MessageTransmitterV2,
      packageId: options.messageTransmitterV2PackageId,
      namedDeps: [
        { name: "deployer", address: options.deployer },
        { name: PackageName.AptosExtensions, address: options.aptosExtensionsPackageId },
        { name: PackageName.CctpExtensions, address: options.cctpExtensionsPackageId },
      ],
      rpc: options.rpc,
      includedArtifacts: options.includedArtifacts,
    })
  );

  // Verify TokenMessengerMinterV2
  console.log("Verifying TokenMessengerMinterV2...\n");
  results.push(
    await verifyPackage({
      packageName: PackageName.TokenMessengerMinterV2,
      packageId: options.tokenMessengerMinterV2PackageId,
      namedDeps: [
        { name: "deployer", address: options.deployer },
        { name: PackageName.AptosExtensions, address: options.aptosExtensionsPackageId },
        { name: PackageName.MessageTransmitterV2, address: options.messageTransmitterV2PackageId },
        { name: PackageName.CctpExtensions, address: options.cctpExtensionsPackageId },
      ],
      rpc: options.rpc,
      includedArtifacts: options.includedArtifacts,
    })
  );

  // Verify StablecoinHandler
  console.log("Verifying StablecoinHandler...\n");
  results.push(
    await verifyPackage({
      packageName: PackageName.StablecoinHandler,
      packageId: options.stablecoinHandlerPackageId,
      namedDeps: [
        { name: "deployer", address: options.deployer },
        { name: PackageName.AptosExtensions, address: options.aptosExtensionsPackageId },
        { name: PackageName.Stablecoin, address: options.stablecoinPackageId },
        { name: PackageName.CctpExtensions, address: options.cctpExtensionsPackageId },
        { name: PackageName.MessageTransmitterV2, address: options.messageTransmitterV2PackageId },
        { name: PackageName.TokenMessengerMinterV2, address: options.tokenMessengerMinterV2PackageId },
      ],
      rpc: options.rpc,
      includedArtifacts: options.includedArtifacts,
    })
  );

  // Summary
  console.log("\n=== Verification Summary ===");
  for (const result of results) {
    const status = result.bytecodeVerified && result.metadataVerified ? "PASS" : "FAIL";
    console.log(
      `${result.packageName}: ${status} (bytecode: ${result.bytecodeVerified}, metadata: ${result.metadataVerified})`
    );
  }
}

/*
Example - yarn verify-all-v2-pkgs --deployer=0x... --rpc=http://localhost:8080 \
  --aptosExtensionsPackageId=0x... --stablecoinPackageId=0x... \
  --cctpExtensionsPackageId=0x... --messageTransmitterV2PackageId=0x... \
  --tokenMessengerMinterV2PackageId=0x... --stablecoinHandlerPackageId=0x...
*/

export default program
  .createCommand("verify-all-v2-pkgs")
  .description("Verify bytecode and metadata of all deployed V2 packages match local source code.")
  .requiredOption("--deployer <string>", "Deployer address")
  .requiredOption("-r, --rpc <string>", "Network RPC URL")
  .requiredOption("--aptosExtensionsPackageId <string>", "AptosExtensions package address")
  .requiredOption("--stablecoinPackageId <string>", "Stablecoin package address")
  .requiredOption("--cctpExtensionsPackageId <string>", "CctpExtensions package address")
  .requiredOption("--messageTransmitterV2PackageId <string>", "MessageTransmitterV2 package address")
  .requiredOption("--tokenMessengerMinterV2PackageId <string>", "TokenMessengerMinterV2 package address")
  .requiredOption("--stablecoinHandlerPackageId <string>", "StablecoinHandler package address")
  .option("--includedArtifacts <string>", "Included artifacts", "none")
  .action(verifyAllV2Packages);
