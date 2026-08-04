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

import { AccountAddress, createObjectAddress, createResourceAddress } from "@aptos-labs/ts-sdk";
import { program } from "commander";

function calculateDeploymentAddresses({ deployer }: { deployer: string }) {
  const deployerAddress = AccountAddress.fromStringStrict(deployer);

  const cctpExtensionsPackageAddress = createResourceAddress(
    deployerAddress,
    new Uint8Array(Buffer.from("cctp_extensions"))
  );

  const messageTransmitterPackageAddress = createResourceAddress(
    deployerAddress,
    new Uint8Array(Buffer.from("message_transmitter_v2"))
  );
  const messageTransmitterObjectAddress = createObjectAddress(
    messageTransmitterPackageAddress,
    new Uint8Array(Buffer.from("MessageTransmitter"))
  );

  const tokenMessengerMinterPackageAddress = createResourceAddress(
    deployerAddress,
    new Uint8Array(Buffer.from("token_messenger_minter_v2"))
  );
  const tokenMessengerMinterObjectAddress = createObjectAddress(
    tokenMessengerMinterPackageAddress,
    new Uint8Array(Buffer.from("TokenMessengerMinter"))
  );

  const stablecoinHandlerPackageAddress = createResourceAddress(
    deployerAddress,
    new Uint8Array(Buffer.from("stablecoin_handler"))
  );
  const stablecoinHandlerObjectAddress = createObjectAddress(
    stablecoinHandlerPackageAddress,
    new Uint8Array(Buffer.from("StablecoinHandler"))
  );

  console.log(`CctpExtensions package address: ${cctpExtensionsPackageAddress.toStringLong()}`);
  console.log(`MessageTransmitterV2 package address: ${messageTransmitterPackageAddress.toStringLong()}`);
  console.log(`MessageTransmitterV2 object address: ${messageTransmitterObjectAddress.toStringLong()}`);
  console.log(`TokenMessengerMinterV2 package address: ${tokenMessengerMinterPackageAddress.toStringLong()}`);
  console.log(`TokenMessengerMinterV2 object address: ${tokenMessengerMinterObjectAddress.toStringLong()}`);
  console.log(`StablecoinHandler package address: ${stablecoinHandlerPackageAddress.toStringLong()}`);
  console.log(`StablecoinHandler object address: ${stablecoinHandlerObjectAddress.toStringLong()}`);
}

/*
Example - yarn calculate-deployment-addresses-v2 --deployer=0x5ba1674a3ffa843ed88aa4a0a051b9a52f76459a8853e5cd62b22bcc488d2765
*/

export default program
  .createCommand("calculate-deployment-addresses-v2")
  .description("Calculate the addresses that the V2 packages will be deployed to.")
  .requiredOption("--deployer <string>", "Deployer address")
  .action(calculateDeploymentAddresses);
