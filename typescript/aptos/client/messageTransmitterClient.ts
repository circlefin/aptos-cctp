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
  MoveOption,
  MoveValue,
  MoveVector,
  U32,
  U64,
  U8,
} from "@aptos-labs/ts-sdk";
import { CctpFunctionScript } from "../utils/cctpFunctionScript";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";
import { PackageName } from "../utils/package";
import { MoveUint32Type, MoveUint64Type } from "@aptos-labs/ts-sdk/src/types";

export class MessageTransmitterClient extends AptosContractClient {
  constructor(aptos: Aptos, packageDeployer: Ed25519Account) {
    super(aptos, PackageName.MessageTransmitter, packageDeployer);
  }

  initializeState = async (
    localDomain: U32,
    attester: AccountAddress,
    maxMessageBodySize: U64,
    version: U32
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.MessageTransmitter, MoveFunction.InitializeMessageTransmitter, [
      localDomain,
      attester,
      maxMessageBodySize,
      version,
    ]);
  };

  publishPackage = async (
    filePath: string,
    aptosExtensionsPackageId: string,
    includedArtifacts: string
  ): Promise<string> => {
    return await this.buildAndPublishPackage(
      `${filePath}/${this.packageName}/`,
      this.packageDeployer,
      PackageName.MessageTransmitter,
      [
        { name: "deployer", address: this.packageDeployer.accountAddress.toString() },
        { name: `${PackageName.AptosExtensions}`, address: aptosExtensionsPackageId },
      ],
      new Uint8Array(Buffer.from(PackageName.MessageTransmitter)),
      includedArtifacts
    );
  };

  replaceMessage = async (
    filePath: string,
    originalMessage: MoveVector<U8>,
    originalAttestation: MoveVector<U8>,
    newMessageBody: MoveOption<MoveVector<U8>>,
    newDestinationCaller: MoveOption<AccountAddress>
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(filePath, CctpFunctionScript.ReplaceMessage, [
      originalMessage,
      originalAttestation,
      newMessageBody,
      newDestinationCaller,
    ]);
  };

  receiveMessage = async (
    filePath: string,
    messageBytes: MoveVector<U8>,
    attestation: MoveVector<U8>
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveScript(filePath, CctpFunctionScript.ReceiveMessage, [messageBytes, attestation]);
  };

  sendMessage = async (
    filePath: string,
    destinationDomain: U32,
    recipient: AccountAddress,
    messageBody: MoveVector<U8>,
    destinationCaller?: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    let moveScript = CctpFunctionScript.SendMessage;
    const functionArgs = [destinationDomain, recipient, messageBody];
    if (destinationCaller) {
      moveScript = CctpFunctionScript.SendMessageWithCaller;
      functionArgs.push(destinationCaller);
    }
    return await this.executeMoveScript(filePath, moveScript, functionArgs);
  };

  enableAttester = async (attester: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Attester, MoveFunction.EnableAttester, [attester.toString()]);
  };

  disableAttester = async (attester: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Attester, MoveFunction.DisableAttester, [attester.toString()]);
  };

  isEnabledAttester = async (attester: AccountAddress): Promise<boolean> => {
    const isEnabledAttester = await this.executeMoveViewFunction(MoveModule.Attester, MoveFunction.IsEnabledAttester, [
      attester.toString(),
    ]);
    return isEnabledAttester[0] == true;
  };

  getEnabledAttester = async (index: number): Promise<AccountAddress> => {
    const enabledAttester = await this.executeMoveViewFunction(MoveModule.Attester, MoveFunction.GetEnabledAttester, [
      index,
    ]);
    return AccountAddress.fromString(enabledAttester[0] as string);
  };

  getNumEnabledAttesters = async (): Promise<MoveUint64Type> => {
    const numEnabledAttesters: MoveValue[] = await this.executeMoveViewFunction(
      MoveModule.Attester,
      MoveFunction.GetNumEnabledAttesters
    );
    return numEnabledAttesters[0] as MoveUint64Type;
  };

  getAttesterManager = async (): Promise<AccountAddress> => {
    const attesterManager = await this.executeMoveViewFunction(MoveModule.Attester, MoveFunction.GetAttesterManager);
    return AccountAddress.fromString(attesterManager[0] as string);
  };

  updateAttesterManager = async (manager: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Attester, MoveFunction.UpdateAttesterManager, [
      manager.toString(),
    ]);
  };

  setSignatureThreshold = async (threshold: number): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Attester, MoveFunction.SetSignatureThreshold, [threshold]);
  };

  getSignatureThreshold = async (): Promise<MoveUint64Type> => {
    const signatureThreshold = await this.executeMoveViewFunction(
      MoveModule.Attester,
      MoveFunction.GetSignatureThreshold
    );
    return signatureThreshold[0] as MoveUint64Type;
  };

  setMaxMessageBodySize = async (size: number): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.MessageTransmitter, MoveFunction.SetMaxMessageBodySize, [size]);
  };

  getLocalDomain = async (): Promise<MoveUint32Type> => {
    const localDomain = await this.executeMoveViewFunction(MoveModule.MessageTransmitter, MoveFunction.LocalDomain);
    return localDomain[0] as MoveUint32Type;
  };

  getVersion = async (): Promise<MoveUint32Type> => {
    const version = await this.executeMoveViewFunction(MoveModule.MessageTransmitter, MoveFunction.Version);
    return version[0] as MoveUint32Type;
  };

  getMaxMessageBodySize = async (): Promise<MoveUint64Type> => {
    const maxMessageBodySize = await this.executeMoveViewFunction(
      MoveModule.MessageTransmitter,
      MoveFunction.MaxMessageBodySize
    );
    return maxMessageBodySize[0] as MoveUint64Type;
  };

  getObjectAddress = (): AccountAddress => {
    return createObjectAddress(AccountAddress.from(this.packageId), "MessageTransmitter");
  };
}
