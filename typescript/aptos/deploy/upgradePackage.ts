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
import { executeTransaction, getAptosClient } from "../utils/helper";
import { Ed25519Account, Ed25519PrivateKey, InputGenerateTransactionPayloadData, MoveVector } from "@aptos-labs/ts-sdk";
import fs from "fs";

async function upgradePackage({
  privateKey,
  rpc,
  payloadFilePath,
  aptosExtensionsPackageId,
  packageId,
}: {
  privateKey: string;
  rpc: string;
  payloadFilePath: string;
  aptosExtensionsPackageId: string;
  packageId: string;
}): Promise<void> {
  const aptos = getAptosClient(rpc);

  const admin = new Ed25519Account({
    privateKey: new Ed25519PrivateKey(privateKey),
  });

  console.log(`Admin account: ${admin.accountAddress}\n`);

  if (!fs.existsSync(payloadFilePath)) {
    throw new Error(`Failed to load payload file: ${payloadFilePath}`);
  }
  const jsonData = JSON.parse(fs.readFileSync(payloadFilePath, "utf-8"));

  if (!jsonData || !jsonData.args || jsonData.args.length < 2 || !jsonData.args[0].value || !jsonData.args[1].value) {
    throw new Error(`Invalid payload file: ${payloadFilePath}`);
  }
  console.log(`Upgrading package using payload: ${payloadFilePath}\n`);

  const metadataBytes: string = jsonData.args[0].value;
  const bytecode: string[] = jsonData.args[1].value;

  const data: InputGenerateTransactionPayloadData = {
    function: `${aptosExtensionsPackageId}::upgradable::upgrade_package`,
    functionArguments: [packageId, MoveVector.U8(metadataBytes), new MoveVector(bytecode.map(MoveVector.U8))],
  };

  await executeTransaction({ aptos, sender: admin, data });

  console.log(`Package upgraded successfully!\n`);
}

/*
Example - yarn upgrade-pkg --privateKey=<privateKey> --rpc=http://localhost:8080 --payloadFilePath=upgrade.json --aptosExtensionsPackageId=0x9b43208bdff59a953f929309b1238ad0126a471002796261f8ce936c59917efb --packageId=0x66535c727de1d398a82593bec9b90be36385f9ad28cc48852123404adbf9bccf
*/

export default program
  .createCommand("upgrade")
  .description("Upgrade the given package")
  .requiredOption("-r, --rpc <string>", "Network RPC URL")
  .requiredOption("--privateKey <string>", "Admin private key")
  .requiredOption("--payloadFilePath <string>", "The publish package JSON payload file path")
  .requiredOption("--aptosExtensionsPackageId <string>", "aptos_extensions package address")
  .requiredOption("--packageId <string>", "address of package to be upgraded")
  .action(upgradePackage);
