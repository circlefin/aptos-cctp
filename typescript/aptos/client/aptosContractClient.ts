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
