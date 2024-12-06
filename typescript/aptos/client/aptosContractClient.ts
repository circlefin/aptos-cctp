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

import {
  Account,
  Aptos,
  CommittedTransactionResponse,
  Ed25519Account,
  createResourceAddress,
  MoveVector,
  AccountAddress,
  MoveValue,
} from "@aptos-labs/ts-sdk";
import { readFileSync } from "fs";
import { PackageName } from "../utils/package";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";
import { CctpFunctionScript } from "../utils/cctpFunctionScript";
import { buildPackage, executeTransaction, getPublishedPackageFromTxOutput, NamedAddress } from "../utils/helper";

export abstract class AptosContractClient {
  protected readonly aptos: Aptos;
  protected readonly packageName: PackageName;
  protected readonly packageDeployer: Ed25519Account;
  packageId: string;

  constructor(aptos: Aptos, packageId: PackageName, packageDeployer: Ed25519Account) {
    this.aptos = aptos;
    this.packageName = packageId;
    this.packageDeployer = packageDeployer;
  }

  abstract initializeState: (...args: any[]) => Promise<CommittedTransactionResponse>;

  abstract publishPackage: (...args: any[]) => Promise<string>;

  abstract getObjectAddress: () => AccountAddress;

  protected executeMoveScript = async (
    filePath: string,
    moveScript: CctpFunctionScript,
    functionArguments: Array<any>,
    signer?: Account
  ): Promise<CommittedTransactionResponse> => {
    // Build a transaction with the script bytecode
    const bytecode = this.loadScriptBytecode(filePath, moveScript);
    const transaction = await this.aptos.transaction.build.simple({
      sender: signer?.accountAddress ?? this.packageDeployer.accountAddress,
      data: {
        bytecode,
        functionArguments,
      },
    });

    // Submit and wait for the transaction to complete
    const pendingTxn = await this.aptos.signAndSubmitTransaction({
      signer: signer ?? this.packageDeployer,
      transaction,
    });
    return this.aptos.waitForTransaction({ transactionHash: pendingTxn.hash });
  };

  protected executeMoveFunction = async (
    module: MoveModule,
    func: MoveFunction,
    functionArguments: any[],
    signer?: Account
  ): Promise<CommittedTransactionResponse> => {
    const transaction = await this.aptos.transaction.build.simple({
      sender: signer?.accountAddress ?? this.packageDeployer.accountAddress,
      data: {
        function: `${this.packageId}::${module}::${func}`,
        functionArguments,
      },
    });

    // Submit and wait for the transaction to complete
    const pendingTxn = await this.aptos.signAndSubmitTransaction({
      signer: signer ?? this.packageDeployer,
      transaction,
    });
    return this.aptos.waitForTransaction({ transactionHash: pendingTxn.hash });
  };

  protected executeMoveViewFunction = async (
    module: MoveModule,
    func: MoveFunction,
    functionArguments?: any[]
  ): Promise<MoveValue[]> => {
    return await this.aptos.view({
      payload: {
        function: `${this.packageId}::${module}::${func}`,
        functionArguments: functionArguments || [],
      },
    });
  };

  protected loadScriptBytecode = (filePath: string, moveScript: CctpFunctionScript): Uint8Array => {
    const scriptFile = this.getScriptFile(filePath, moveScript);
    const buffer = readFileSync(scriptFile);
    return Uint8Array.from(buffer);
  };

  protected getScriptFile = (filePath: string, moveScript: CctpFunctionScript): string => {
    let builtPackage;
    switch (this.packageName) {
      case PackageName.MessageTransmitter:
        builtPackage = "MessageTransmitter";
        break;
      case PackageName.TokenMessengerMinter:
        builtPackage = "TokenMessengerMinter";
        break;
      default:
        console.log("Unknown package has been defined. Please investigate.", this.packageName);
        break;
    }
    return `${filePath}/${this.packageName}/build/${builtPackage}/bytecode_scripts/${moveScript}.mv`;
  };

  protected buildAndPublishPackage = async (
    packageDir: string,
    deployer: Ed25519Account,
    packageName: string,
    namedDeps: NamedAddress[],
    seed: Uint8Array,
    includedArtifacts: string
  ): Promise<string> => {
    const expectedCodeAddress = (await createResourceAddress(deployer.accountAddress, seed)).toString();
    const { metadataBytes, bytecode } = await buildPackage(
      packageDir,
      packageName,
      [
        {
          name: packageName,
          address: expectedCodeAddress,
        },
        ...namedDeps,
      ],
      includedArtifacts
    );
    const functionArguments = [MoveVector.U8(metadataBytes), new MoveVector(bytecode.map(MoveVector.U8))];
    functionArguments.unshift(MoveVector.U8(seed!));
    const publishExtensionsTxOutput = await executeTransaction({
      aptos: this.aptos,
      sender: deployer,
      data: {
        function: "0x1::resource_account::create_resource_account_and_publish_package",
        functionArguments,
      },
    });

    this.packageId = getPublishedPackageFromTxOutput(publishExtensionsTxOutput);
    console.log(`Deployed ${packageName} package at ${this.packageId}\n`);
    return this.packageId;
  };
}
