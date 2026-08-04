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
import {
  AccountAddress,
  Aptos,
  CommittedTransactionResponse,
  Ed25519Account,
  createObjectAddress,
  MoveVector,
  U8,
  U32,
  U64,
} from "@aptos-labs/ts-sdk";
import { PackageName } from "../utils/package";
import { CctpFunctionScript } from "../utils/cctpFunctionScript";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";

export class StablecoinHandlerClient extends AptosContractClient {
  constructor(aptos: Aptos, packageDeployer: Ed25519Account) {
    super(aptos, PackageName.StablecoinHandler, packageDeployer);
  }

  initializeState = async (): Promise<CommittedTransactionResponse> => {
    return Promise.resolve(undefined); // do nothing
  };

  getObjectAddress = (): AccountAddress => {
    return createObjectAddress(AccountAddress.from(this.packageId), "StablecoinHandler");
  };

  signerAddress = (): AccountAddress => {
    return this.getObjectAddress();
  };

  publishPackage = async (
    filePath: string,
    aptosExtensionsPackageId: string,
    stablecoinPackageId: string,
    cctpExtensionsPackageId: string,
    messageTransmitterV2PackageId: string,
    tokenMessengerMinterV2PackageId: string,
    includedArtifacts: string
  ): Promise<string> => {
    return await this.buildAndPublishPackage(
      `${filePath}/${this.packageName}/`,
      this.packageDeployer,
      PackageName.StablecoinHandler,
      [
        { name: "deployer", address: this.packageDeployer.accountAddress.toString() },
        { name: `${PackageName.AptosExtensions}`, address: aptosExtensionsPackageId },
        { name: `${PackageName.Stablecoin}`, address: stablecoinPackageId },
        { name: `${PackageName.CctpExtensions}`, address: cctpExtensionsPackageId },
        { name: `${PackageName.MessageTransmitterV2}`, address: messageTransmitterV2PackageId },
        { name: `${PackageName.TokenMessengerMinterV2}`, address: tokenMessengerMinterV2PackageId },
      ],
      new Uint8Array(Buffer.from(PackageName.StablecoinHandler)),
      includedArtifacts
    );
  };

  /**
   * Execute deposit_for_burn script to burn stablecoin for cross-chain transfer
   */
  depositForBurn = async (
    filePath: string,
    caller: Ed25519Account,
    amount: U64,
    destinationDomain: U32,
    mintRecipient: AccountAddress,
    destinationCaller: AccountAddress,
    burnToken: AccountAddress,
    maxFee: U64,
    minFinalityThreshold: U32
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(
      filePath,
      CctpFunctionScript.DepositForBurnV2,
      [amount, destinationDomain, mintRecipient, destinationCaller, burnToken, maxFee, minFinalityThreshold],
      caller
    );
  };

  /**
   * Execute deposit_for_burn_with_hook script to burn stablecoin for cross-chain transfer with hook data
   * Note: hook_data must be non-empty or the script will abort
   */
  depositForBurnWithHook = async (
    filePath: string,
    caller: Ed25519Account,
    amount: U64,
    destinationDomain: U32,
    mintRecipient: AccountAddress,
    destinationCaller: AccountAddress,
    burnToken: AccountAddress,
    maxFee: U64,
    minFinalityThreshold: U32,
    hookData: MoveVector<U8>
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(
      filePath,
      CctpFunctionScript.DepositForBurnWithHookV2,
      [amount, destinationDomain, mintRecipient, destinationCaller, burnToken, maxFee, minFinalityThreshold, hookData],
      caller
    );
  };

  /**
   * Execute receive_message script to receive cross-chain message and mint stablecoin
   */
  receiveMessage = async (
    filePath: string,
    caller: Ed25519Account,
    message: MoveVector<U8>,
    attestation: MoveVector<U8>
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(
      filePath,
      CctpFunctionScript.ReceiveMessageV2,
      [message, attestation],
      caller
    );
  };

  /**
   * Execute mint script to mint stablecoin tokens to a recipient.
   * The minter must be a configured minter with sufficient allowance.
   */
  mint = async (
    filePath: string,
    minter: Ed25519Account,
    amount: U64,
    mintRecipient: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(
      filePath,
      CctpFunctionScript.MintV2,
      [amount, mintRecipient],
      minter
    );
  };

  /**
   * Execute send_message script to send a general cross-chain message.
   */
  sendMessage = async (
    filePath: string,
    caller: Ed25519Account,
    destinationDomain: U32,
    recipient: AccountAddress,
    destinationCaller: AccountAddress,
    minFinalityThreshold: U32,
    messageBody: MoveVector<U8>
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(
      filePath,
      CctpFunctionScript.SendMessageV2,
      [destinationDomain, recipient, destinationCaller, minFinalityThreshold, messageBody],
      caller
    );
  };

  getHandlerAddress = async (): Promise<AccountAddress> => {
    const handlerAddress = await this.executeMoveViewFunction(MoveModule.Handler, MoveFunction.HandlerAddress, []);
    return AccountAddress.fromString(handlerAddress[0] as string);
  };

  getSupportedToken = async (): Promise<AccountAddress> => {
    const supportedToken = await this.executeMoveViewFunction(MoveModule.Handler, MoveFunction.SupportedToken, []);
    return AccountAddress.fromString(supportedToken[0] as string);
  };
}
