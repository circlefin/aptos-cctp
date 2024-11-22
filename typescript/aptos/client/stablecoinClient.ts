/*
 * Copyright (c) 2024, Circle Internet Group, Inc.
 * All rights reserved.
 *
 * Circle Internet Group, Inc. CONFIDENTIAL
 *
 * This file includes unpublished proprietary source code of Circle Internet
 * Group, Inc. The copyright notice above does not evidence any actual or
 * intended publication of such source code. Disclosure of this source code
 * or any related proprietary information is strictly prohibited without
 * the express written permission of Circle Internet Group, Inc.
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
