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

import { AptosContractClient } from "./aptosContractClient";
import { Account, AccountAddress, Aptos, CommittedTransactionResponse, Ed25519Account, UserTransactionResponse } from "@aptos-labs/ts-sdk";
import { PackageName } from "../utils/package";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";
import { getEventByType } from "../utils/helper";

export class CctpExtensionsClient extends AptosContractClient {
  constructor(aptos: Aptos, packageDeployer: Ed25519Account) {
    super(aptos, PackageName.CctpExtensions, packageDeployer);
  }

  initializeState = async (): Promise<CommittedTransactionResponse> => {
    return Promise.resolve(undefined); // do nothing
  };

  getObjectAddress = (): AccountAddress => {
    throw new Error("Method not supported.");
  };

  rescuer = async (objectAddress: AccountAddress): Promise<AccountAddress> => {
    const rescuer = await this.executeMoveViewFunction(MoveModule.Rescuable, MoveFunction.Rescuer, [
      objectAddress.toString(),
    ]);
    return AccountAddress.fromString(rescuer[0] as string);
  };

  updateRescuer = async (
    signer: Account,
    objectAddress: AccountAddress,
    newRescuer: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Rescuable,
      MoveFunction.UpdateRescuer,
      [objectAddress.toString(), newRescuer.toString()],
      signer
    );
  };

  rescueFungibleAsset = async (
    signer: Account,
    objectAddress: AccountAddress,
    tokenMetadata: AccountAddress,
    recipientAddress: AccountAddress,
    amount: number
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Rescuable,
      MoveFunction.RescueFungibleAsset,
      [objectAddress.toString(), tokenMetadata.toString(), recipientAddress.toString(), amount],
      signer
    );
  };

  publishPackage = async (filePath: string, aptosExtensionsPackageId: string, includedArtifacts: string): Promise<string> => {
    return await this.buildAndPublishPackage(
      `${filePath}/${this.packageName}/`,
      this.packageDeployer,
      "cctp_extensions",
      [
        { name: "deployer", address: this.packageDeployer.accountAddress.toString() },
        { name: `${PackageName.AptosExtensions}`, address: aptosExtensionsPackageId },
      ],
      new Uint8Array(Buffer.from("cctp_extensions")),
      includedArtifacts
    );
  };

  // Event verification helpers
  getRescuerChangedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::rescuable::RescuerChanged`);
  };
}
