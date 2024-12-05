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
  Account,
  AccountAddress,
  Aptos,
  CommittedTransactionResponse,
  createObjectAddress,
  Ed25519Account,
  MoveOption,
  MoveVector,
  U32,
  U64,
  U8,
} from "@aptos-labs/ts-sdk";
import { PackageName } from "../utils/package";
import { CctpFunctionScript } from "../utils/cctpFunctionScript";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";
import { MoveUint32Type, MoveUint64Type } from "@aptos-labs/ts-sdk/src/types";

export class TokenMessengerMinterClient extends AptosContractClient {
  constructor(aptos: Aptos, packageDeployer: Ed25519Account) {
    super(aptos, PackageName.TokenMessengerMinter, packageDeployer);
  }

  initializeState = async (
    messageBodyVersion: U32,
    tokenController: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.TokenMessengerMinter,
      MoveFunction.InitializeTokenMessengerMinter,
      [messageBodyVersion, tokenController]
    );
  };

  publishPackage = async (
    filePath: string,
    aptosExtensionsPackageId: string,
    messageTransmitterPackageId: string,
    stablecoinPackageId: string,
    includedArtifacts: string
  ): Promise<string> => {
    return await this.buildAndPublishPackage(
      `${filePath}/${this.packageName}/`,
      this.packageDeployer,
      PackageName.TokenMessengerMinter,
      [
        { name: "deployer", address: this.packageDeployer.accountAddress.toString() },
        { name: `${PackageName.AptosExtensions}`, address: aptosExtensionsPackageId },
        { name: `${PackageName.MessageTransmitter}`, address: messageTransmitterPackageId },
        { name: `${PackageName.Stablecoin}`, address: stablecoinPackageId },
      ],
      new Uint8Array(Buffer.from(PackageName.TokenMessengerMinter)),
      includedArtifacts
    );
  };

  getObjectAddress = (): AccountAddress => {
    return createObjectAddress(AccountAddress.from(this.packageId), "TokenMessengerMinter");
  };

  depositForBurn = async (
    filePath: string,
    signer: Account,
    amount: U64,
    destinationDomain: U32,
    mintRecipient: AccountAddress,
    burnToken: AccountAddress,
    destinationCaller?: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    let moveScript = CctpFunctionScript.DepositForBurn;
    const functionArgs = [amount, destinationDomain, mintRecipient, burnToken];
    if (destinationCaller) {
      moveScript = CctpFunctionScript.DepositForBurnWithCaller;
      functionArgs.push(destinationCaller);
    }
    return await this.executeMoveScript(filePath, moveScript, functionArgs, signer);
  };

  replaceDepositForBurn = async (
    filePath: string,
    originalMessage: MoveVector<U8>,
    originalAttestation: MoveVector<U8>,
    newDestinationCaller: MoveOption<AccountAddress>,
    newMintRecipient: MoveOption<AccountAddress>
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(filePath, CctpFunctionScript.ReplaceDepositForBurn, [
      originalMessage,
      originalAttestation,
      newDestinationCaller,
      newMintRecipient,
    ]);
  };

  handleReceiveMessage = async (
    filePath: string,
    messageBytes: MoveVector<U8>,
    attestation: MoveVector<U8>
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(filePath, CctpFunctionScript.HandleReceiveMessage, [messageBytes, attestation]);
  };

  addRemoteTokenMessenger = async (
    remoteDomain: U32,
    remoteTokenMessenger: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenMessenger, MoveFunction.AddRemoteTokenMessenger, [
      remoteDomain,
      remoteTokenMessenger.toString(),
    ]);
  };

  removeRemoteTokenMessenger = async (remoteDomain: U32): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenMessenger, MoveFunction.RemoveRemoteTokenMessenger, [
      remoteDomain,
    ]);
  };

  getRemoteTokenMessenger = async (remoteDomain: U32): Promise<AccountAddress> => {
    const remoteTokenMessenger = await this.executeMoveViewFunction(
      MoveModule.TokenMessenger,
      MoveFunction.GetRemoteTokenMessenger,
      [remoteDomain]
    );
    return AccountAddress.fromString(remoteTokenMessenger[0] as string);
  };

  getMessageBodyVersion = async (): Promise<MoveUint32Type> => {
    const messageBodyVersion = await this.executeMoveViewFunction(
      MoveModule.TokenMessenger,
      MoveFunction.MessageBodyVersion
    );
    return messageBodyVersion[0] as MoveUint32Type;
  };

  getNumRemoteTokenMessenger = async (): Promise<MoveUint64Type> => {
    const numRemoteTokenMessengers = await this.executeMoveViewFunction(
      MoveModule.TokenMessenger,
      MoveFunction.NumRemoteTokenMessengers
    );
    return numRemoteTokenMessengers[0] as MoveUint64Type;
  };

  getTokenController = async (): Promise<AccountAddress> => {
    const tokenController = await this.executeMoveViewFunction(
      MoveModule.TokenController,
      MoveFunction.GetTokenController
    );
    return AccountAddress.fromString(tokenController[0] as string);
  };

  getLinkedToken = async (remoteDomain: U32, remoteToken: AccountAddress): Promise<AccountAddress> => {
    const localToken = await this.executeMoveViewFunction(MoveModule.TokenController, MoveFunction.GetLinkedToken, [
      remoteDomain,
      remoteToken,
    ]);
    return AccountAddress.fromString(localToken[0] as string);
  };

  setTokenController = async (controllerAddress: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenController, MoveFunction.SetTokenController, [
      controllerAddress.toString(),
    ]);
  };

  setMaxBurnAmountPerMessage = async (
    tokenAddress: AccountAddress,
    amount: U64
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenController, MoveFunction.SetMaxBurnAmountPerMessage, [
      tokenAddress.toString(),
      amount,
    ]);
  };

  linkTokenPair = async (
    localToken: AccountAddress,
    remoteDomain: U32,
    remoteTokenAddress: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenController, MoveFunction.LinkTokenPair, [
      localToken.toString(),
      remoteDomain,
      remoteTokenAddress.toString(),
    ]);
  };

  unlinkTokenPair = async (
    remoteDomain: number,
    remoteTokenAddress: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenController, MoveFunction.UnlinkTokenPair, [
      remoteDomain,
      remoteTokenAddress.toString(),
    ]);
  };

  mint = async (
    filePath: string,
    minter: Ed25519Account,
    amount: U64,
    mintRecipient: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(filePath, CctpFunctionScript.Mint, [amount, mintRecipient], minter);
  };

  signerAddress = (): AccountAddress => {
    return this.getObjectAddress();
  };
}
