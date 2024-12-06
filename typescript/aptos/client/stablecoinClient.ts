/**
 * Copyright (c) 2024, Circle Internet Group, Inc. All rights reserved.
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
import {
  AccountAddress,
  Aptos,
  CommittedTransactionResponse,
  createObjectAddress,
  Ed25519Account,
  U8,
  U64,
} from "@aptos-labs/ts-sdk";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";
import { PackageName } from "../utils/package";

export class StablecoinClient extends AptosContractClient {
  constructor(aptos: Aptos, packageDeployer: Ed25519Account) {
    super(aptos, PackageName.Stablecoin, packageDeployer);
  }

  initializeState = async (
    name: string,
    symbol: string,
    decimals: U8,
    iconUri: string,
    projectUri: string
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Stablecoin, MoveFunction.InitializeV1, [
      name,
      symbol,
      decimals,
      iconUri,
      projectUri,
    ]);
  };

  publishPackage = async (filePath: string, aptosExtensionsPackageId: string): Promise<string> => {
    return await this.buildAndPublishPackage(
      `${filePath}/${this.packageName}/`,
      this.packageDeployer,
      PackageName.Stablecoin,
      [
        { name: "deployer", address: this.packageDeployer.accountAddress.toString() },
        { name: `${PackageName.AptosExtensions}`, address: aptosExtensionsPackageId },
      ],
      new Uint8Array(Buffer.from(PackageName.Stablecoin)),
      "sparse"
    );
  };

  configureController = async (
    controller: AccountAddress,
    minter: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Treasury, MoveFunction.ConfigureController, [
      controller,
      minter.toString(),
    ]);
  };

  configureMinter = async (signer: Ed25519Account, allowance: U64): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Treasury, MoveFunction.ConfigureMinter, [allowance], signer);
  };

  getObjectAddress = (): AccountAddress => {
    return createObjectAddress(AccountAddress.from(this.packageId), "stablecoin");
  };
}
