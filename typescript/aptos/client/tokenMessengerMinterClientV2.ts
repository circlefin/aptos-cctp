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
  createObjectAddress,
  Ed25519Account,
  U32,
  U64,
  UserTransactionResponse
} from "@aptos-labs/ts-sdk";
import { PackageName } from "../utils/package";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";
import { MoveUint32Type, MoveUint64Type } from "@aptos-labs/ts-sdk/src/types";
import { getEventByType } from "../utils/helper";

export class TokenMessengerMinterClientV2 extends AptosContractClient {
  constructor(aptos: Aptos, packageDeployer: Ed25519Account) {
    super(aptos, PackageName.TokenMessengerMinterV2, packageDeployer);
  }

  initializeState = async (
    messageBodyVersion: U32,
    tokenController: AccountAddress,
    feeRecipient: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Initializer,
      MoveFunction.InitializeTokenMessengerMinter,
      [messageBodyVersion, tokenController, feeRecipient]
    );
  };

  publishPackage = async (
    filePath: string,
    aptosExtensionsPackageId: string,
    messageTransmitterPackageId: string,
    cctpExtensionsPackageId: string,
    includedArtifacts: string
  ): Promise<string> => {
    return await this.buildAndPublishPackage(
      `${filePath}/${this.packageName}/`,
      this.packageDeployer,
      PackageName.TokenMessengerMinterV2,
      [
        { name: "deployer", address: this.packageDeployer.accountAddress.toString() },
        { name: `${PackageName.AptosExtensions}`, address: aptosExtensionsPackageId },
        { name: `${PackageName.MessageTransmitterV2}`, address: messageTransmitterPackageId },
        { name: `${PackageName.CctpExtensions}`, address: cctpExtensionsPackageId },
      ],
      new Uint8Array(Buffer.from(PackageName.TokenMessengerMinterV2)),
      includedArtifacts
    );
  };

  getObjectAddress = (): AccountAddress => {
    return createObjectAddress(AccountAddress.from(this.packageId), "TokenMessengerMinter");
  };

  addRemoteTokenMessenger = async (
    remoteDomain: U32,
    remoteTokenMessenger: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenMessengerMinter, MoveFunction.AddRemoteTokenMessenger, [
      remoteDomain,
      remoteTokenMessenger.toString(),
    ]);
  };

  removeRemoteTokenMessenger = async (remoteDomain: U32): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenMessengerMinter, MoveFunction.RemoveRemoteTokenMessenger, [
      remoteDomain,
    ]);
  };

  getRemoteTokenMessenger = async (remoteDomain: U32): Promise<AccountAddress> => {
    const remoteTokenMessenger = await this.executeMoveViewFunction(
      MoveModule.TokenMessengerMinter,
      MoveFunction.GetRemoteTokenMessenger,
      [remoteDomain]
    );
    return AccountAddress.fromString(remoteTokenMessenger[0] as string);
  };

  getMessageBodyVersion = async (): Promise<MoveUint32Type> => {
    const messageBodyVersion = await this.executeMoveViewFunction(
      MoveModule.TokenMessengerMinter,
      MoveFunction.MessageBodyVersion
    );
    return messageBodyVersion[0] as MoveUint32Type;
  };

  getNumRemoteTokenMessenger = async (): Promise<MoveUint64Type> => {
    const numRemoteTokenMessengers = await this.executeMoveViewFunction(
      MoveModule.TokenMessengerMinter,
      MoveFunction.NumRemoteTokenMessengers
    );
    return numRemoteTokenMessengers[0] as MoveUint64Type;
  };

  getMaxBurnAmountPerMessage = async (token: AccountAddress): Promise<MoveUint64Type> => {
    const maxBurnAmountPerMessage = await this.executeMoveViewFunction(
      MoveModule.TokenMessengerMinter,
      MoveFunction.MaxBurnAmountPerMessage,
      [token]
    );
    return maxBurnAmountPerMessage[0] as MoveUint64Type;
  };

  getNumLinkedTokens = async (): Promise<MoveUint64Type> => {
    const numLinkedTokens = await this.executeMoveViewFunction(MoveModule.TokenController, MoveFunction.GetNumLinkedTokens);
    return numLinkedTokens[0] as MoveUint64Type;
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
    remoteDomain: U32,
    remoteTokenAddress: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.TokenController, MoveFunction.UnlinkTokenPair, [
      remoteDomain,
      remoteTokenAddress.toString(),
    ]);
  };

  /**
   * Register a handler for a specific token.
   * The handler will be authorized to call burn/mint operations for that token.
   */
  registerHandler = async (
    tokenAddress: AccountAddress,
    handlerAddress: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.HandlerRegistry, MoveFunction.RegisterHandler, [
      tokenAddress.toString(),
      handlerAddress.toString(),
    ]);
  };

  /**
   * Deregister a handler for a specific token.
   */
  deregisterHandler = async (tokenAddress: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.HandlerRegistry, MoveFunction.DeregisterHandler, [
      tokenAddress.toString(),
    ]);
  };

  signerAddress = (): AccountAddress => {
    return this.getObjectAddress();
  };

  /**
   * Set the minimum fee for a specific token.
   * The caller must be the min_fee_controller (deployer by default).
   * @param tokenAddress The token address to set the fee for
   * @param minFee The minimum fee (u256 value, e.g., 100000 = 1% with MIN_FEE_MULTIPLIER = 10,000,000)
   */
  setMinFee = async (
    tokenAddress: AccountAddress,
    minFee: bigint
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.FeeController, MoveFunction.SetMinFee, [
      tokenAddress.toString(),
      minFee.toString(),
    ]);
  };

  /**
   * Get the minimum fee for a specific token.
   */
  getMinFee = async (tokenAddress: AccountAddress): Promise<bigint> => {
    const minFee = await this.executeMoveViewFunction(MoveModule.FeeController, MoveFunction.GetMinFee, [
      tokenAddress.toString(),
    ]);
    return BigInt(minFee[0] as string);
  };

  /**
   * Get the fee recipient address.
   */
  getFeeRecipient = async (): Promise<AccountAddress> => {
    const feeRecipient = await this.executeMoveViewFunction(MoveModule.FeeController, MoveFunction.GetFeeRecipient);
    return AccountAddress.fromString(feeRecipient[0] as string);
  };

  getMinFeeController = async (): Promise<AccountAddress> => {
    const minFeeController = await this.executeMoveViewFunction(
      MoveModule.FeeController,
      MoveFunction.GetMinFeeController
    );
    return AccountAddress.fromString(minFeeController[0] as string);
  };

  setFeeRecipient = async (newFeeRecipient: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.FeeController, MoveFunction.SetFeeRecipient, [
      newFeeRecipient.toString(),
    ]);
  };

  setMinFeeController = async (newMinFeeController: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.FeeController, MoveFunction.SetMinFeeController, [
      newMinFeeController.toString(),
    ]);
  };

  isDenylisted = async (address: AccountAddress): Promise<boolean> => {
    const isDenylisted = await this.executeMoveViewFunction(MoveModule.Denylistable, MoveFunction.IsDenylisted, [
      address.toString(),
    ]);
    return isDenylisted[0] as boolean;
  };

  getDenylister = async (): Promise<AccountAddress> => {
    const denylister = await this.executeMoveViewFunction(MoveModule.Denylistable, MoveFunction.GetDenylister);
    return AccountAddress.fromString(denylister[0] as string);
  };

  denylist = async (address: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Denylistable, MoveFunction.Denylist, [address.toString()]);
  };

  undenylist = async (address: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Denylistable, MoveFunction.Undenylist, [address.toString()]);
  };

  updateDenylister = async (newDenylister: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Denylistable, MoveFunction.UpdateDenylister, [
      newDenylister.toString(),
    ]);
  };

  isHandlerRegistered = async (tokenAddress: AccountAddress): Promise<boolean> => {
    const isRegistered = await this.executeMoveViewFunction(
      MoveModule.HandlerRegistry,
      MoveFunction.IsHandlerRegistered,
      [tokenAddress.toString()]
    );
    return isRegistered[0] as boolean;
  };

  getHandler = async (tokenAddress: AccountAddress): Promise<AccountAddress> => {
    const handler = await this.executeMoveViewFunction(MoveModule.HandlerRegistry, MoveFunction.GetHandler, [
      tokenAddress.toString(),
    ]);
    return AccountAddress.fromString(handler[0] as string);
  };

  // Event verification helpers
  getRemoteTokenMessengerAddedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::token_messenger_minter::RemoteTokenMessengerAdded`);
  };

  getRemoteTokenMessengerRemovedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::token_messenger_minter::RemoteTokenMessengerRemoved`);
  };

  getTokenPairLinkedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::token_controller::TokenPairLinked`);
  };

  getTokenPairUnlinkedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::token_controller::TokenPairUnlinked`);
  };

  getSetBurnLimitPerMessageEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::token_controller::SetBurnLimitPerMessage`);
  };

  getSetTokenControllerEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::token_controller::SetTokenController`);
  };

  getDenylistedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::denylistable::Denylisted`);
  };

  getUnDenylistedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::denylistable::UnDenylisted`);
  };

  getDenylisterChangedEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::denylistable::DenylisterChanged`);
  };

  getFeeRecipientSetEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::fee_controller::FeeRecipientSet`);
  };

  getMinFeeControllerSetEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::fee_controller::MinFeeControllerSet`);
  };

  getMinFeeSetEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::fee_controller::MinFeeSet`);
  };

  getHandlerRegisteredEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::handler_registry::HandlerRegistered`);
  };

  getHandlerDeregisteredEvent = (txResponse: CommittedTransactionResponse) => {
    return getEventByType(txResponse as UserTransactionResponse, `${this.packageId}::handler_registry::HandlerDeregistered`);
  };
}
