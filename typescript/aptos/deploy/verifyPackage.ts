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

import { strict as assert } from "assert";
import { execSync } from "child_process";
import { program } from "commander";
import {
  buildPackage,
  formatNamedAddresses,
  getAptosClient,
  getPackageBytecode,
  NamedAddress,
  parseNamedAddresses,
} from "../utils/helper";

type BytecodeVerificationResult = {
  packageName: string;
  bytecodeVerified: boolean;
  metadataVerified: boolean;
};

export async function verifyPackage({
  packageName,
  packageId,
  namedDeps,
  rpc,
  includedArtifacts,
}: {
  packageName: string;
  packageId: string;
  namedDeps: NamedAddress[];
  rpc: string;
  includedArtifacts: string;
}): Promise<BytecodeVerificationResult> {
  const aptos = getAptosClient(rpc);
  const namedAddresses = [...namedDeps, { name: packageName, address: packageId }];

  const localModuleBytecode = (
    await buildPackage(`packages/${packageName}/`, packageName, namedAddresses, includedArtifacts)
  ).bytecode;
  const remoteModuleBytecode = await getPackageBytecode(aptos, packageId);

  // Comparing remote bytecode against local compilation
  // Local bytecode list is arranged according to the module dependency hierarchy
  // For simplicity, we compare the sorted list of bytecode
  localModuleBytecode.sort();
  remoteModuleBytecode.sort();

  let bytecodeVerified = false;
  try {
    assert.deepStrictEqual(localModuleBytecode, remoteModuleBytecode);
    bytecodeVerified = true;
  } catch (e) {
    console.error(e);
  }

  // Begin verifying package metadata
  // Setting to enable or disable source code verification
  const verifyMetadataCommand = `make verify-metadata \
    package="${packageName}" \
    package_id="${packageId}" \
    url="${rpc}" \
    named_addresses="${formatNamedAddresses(namedAddresses)}" \
    included_artifacts="${includedArtifacts}"`;

  const result = execSync(verifyMetadataCommand, { encoding: "utf-8" });
  const metadataVerified = result.includes("Successfully verified source of package");

  return { packageName, bytecodeVerified, metadataVerified };
}

/*
Example - yarn verify-pkg --packageName=message_transmitter --rpc=http://localhost:8080 --packageId=0x66535c727de1d398a82593bec9b90be36385f9ad28cc48852123404adbf9bccf --namedDeps aptos_extensions=0x9b43208bdff59a953f929309b1238ad0126a471002796261f8ce936c59917efb,deployer=0x5ba1674a3ffa843ed88aa4a0a051b9a52f76459a8853e5cd62b22bcc488d2765
*/

export default program
  .createCommand("verify-pkg")
  .description("Verify bytecode and metadata of a deployed package match local source code.")
  .requiredOption("--packageName <string>", "The name of the package to verify.")
  .requiredOption("--packageId <string>", "The address where the package is located.")
  .requiredOption("--namedDeps <string>", "Named dependency addresses of the deployed package.")
  .requiredOption("-r, --rpc <string>", "Network RPC URL")
  .option("--includedArtifacts", "Whether source code verification was enabled during package deployment.", "sparse")
  .action(async (options) => {
    const namedDeps = parseNamedAddresses(options.namedDeps);
    const result = await verifyPackage(Object.assign(options, { namedDeps }));
    console.log(result);
  });
