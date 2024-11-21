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

import { AccountAddress, createObjectAddress, createResourceAddress } from "@aptos-labs/ts-sdk";
import { program } from "commander";

function calculateDeploymentAddresses({ deployer }: { deployer: string }) {
  const messageTransmitterPackageAddress = createResourceAddress(
    AccountAddress.fromStringStrict(deployer),
    new Uint8Array(Buffer.from("message_transmitter"))
  );
  const messageTransmitterObjectAddress = createObjectAddress(
    messageTransmitterPackageAddress,
    new Uint8Array(Buffer.from("MessageTransmitter"))
  );

  const tokenMessengerMinterPackageAddress = createResourceAddress(
    AccountAddress.fromStringStrict(deployer),
    new Uint8Array(Buffer.from("token_messenger_minter"))
  );
  const tokenMessengerMinterObjectAddress = createObjectAddress(
    tokenMessengerMinterPackageAddress,
    new Uint8Array(Buffer.from("TokenMessengerMinter"))
  );

  console.log(`MessageTransmitter package address: ${messageTransmitterPackageAddress.toStringLong()}`);
  console.log(`TokenMessengerMinter package address: ${tokenMessengerMinterPackageAddress.toStringLong()}`);
  console.log(`MessageTransmitter object address: ${messageTransmitterObjectAddress.toStringLong()}`);
  console.log(`TokenMessengerMinter object address: ${tokenMessengerMinterObjectAddress.toStringLong()}`);
}

/*
Example - yarn calculate-deployment-addresses  --deployer=0x5ba1674a3ffa843ed88aa4a0a051b9a52f76459a8853e5cd62b22bcc488d2765
*/

export default program
  .createCommand("calculate-deployment-addresses")
  .description("Calculate the addresses that the packages will be deployed to.")
  .requiredOption("--deployer <string>", "Deployer address")
  .action(calculateDeploymentAddresses);
