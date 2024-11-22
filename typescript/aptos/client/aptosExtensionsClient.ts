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
import { Account, AccountAddress, Aptos, CommittedTransactionResponse, Ed25519Account } from "@aptos-labs/ts-sdk";
import { PackageName } from "../utils/package";
import { MoveModule } from "../utils/moveModule";
import { MoveFunction } from "../utils/moveFunction";

export class AptosExtensionsClient extends AptosContractClient {
  constructor(aptos: Aptos, packageDeployer: Ed25519Account) {
    super(aptos, PackageName.AptosExtensions, packageDeployer);
  }

  initializeState = async (): Promise<CommittedTransactionResponse> => {
    return Promise.resolve(undefined); // do nothing
  };

  getObjectAddress = (): AccountAddress => {
    throw new Error("Method not supported.");
  };

  pause = async (signer: Account, objectAddress: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Pausable, MoveFunction.Pause, [objectAddress.toString()], signer);
  };

  unpause = async (signer: Account, objectAddress: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Pausable,
      MoveFunction.Unpause,
      [objectAddress.toString()],
      signer
    );
  };

  updatePauser = async (
    signer: Account,
    objectAddress: AccountAddress,
    newPauser: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Pausable,
      MoveFunction.UpdatePauser,
      [objectAddress.toString(), newPauser.toString()],
      signer
    );
  };

  pauser = async (objectAddress: AccountAddress): Promise<AccountAddress> => {
    const pauser = await this.executeMoveViewFunction(MoveModule.Pausable, MoveFunction.Pauser, [
      objectAddress.toString(),
    ]);
    return AccountAddress.fromString(pauser[0] as string);
  };

  isPaused = async (objectAddress: AccountAddress): Promise<boolean> => {
    const isPaused = await this.executeMoveViewFunction(MoveModule.Pausable, MoveFunction.IsPaused, [
      objectAddress.toString(),
    ]);
    return isPaused[0] as boolean;
  };

  transferOwnership = async (
    signer: Account,
    objectAddress: AccountAddress,
    newOwner: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Ownable,
      MoveFunction.TransferOwnership,
      [objectAddress.toString(), newOwner.toString()],
      signer
    );
  };

  acceptOwnership = async (signer: Account, objectAddress: AccountAddress): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Ownable,
      MoveFunction.AcceptOwnership,
      [objectAddress.toString()],
      signer
    );
  };

  owner = async (objectAddress: AccountAddress): Promise<AccountAddress> => {
    const owner = await this.executeMoveViewFunction(MoveModule.Ownable, MoveFunction.Owner, [
      objectAddress.toString(),
    ]);
    return AccountAddress.fromString(owner[0] as string);
  };

  pendingOwner = async (objectAddress: AccountAddress): Promise<string | AccountAddress> => {
    const pendingOwner = await this.executeMoveViewFunction(MoveModule.Ownable, MoveFunction.PendingOwner, [
      objectAddress.toString(),
    ]);
    return (pendingOwner[0] as any).vec.length == 0 ? "" : AccountAddress.fromString((pendingOwner[0] as any).vec[0]);
  };

  changeAdmin = async (
    signer: Account,
    packageId: string,
    newOwner: AccountAddress
  ): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(
      MoveModule.Manageable,
      MoveFunction.ChangeAdmin,
      [packageId, newOwner.toString()],
      signer
    );
  };

  acceptAdmin = async (signer: Account, packageId: string): Promise<CommittedTransactionResponse> => {
    return await this.executeMoveFunction(MoveModule.Manageable, MoveFunction.AcceptAdmin, [packageId], signer);
  };

  admin = async (packageId: string): Promise<AccountAddress> => {
    const owner = await this.executeMoveViewFunction(MoveModule.Manageable, MoveFunction.Admin, [packageId]);
    return AccountAddress.fromString(owner[0] as string);
  };

  pendingAdmin = async (packageId: string): Promise<string | AccountAddress> => {
    const pendingAdmin = await this.executeMoveViewFunction(MoveModule.Manageable, MoveFunction.PendingAdmin, [
      packageId,
    ]);
    return (pendingAdmin[0] as any).vec.length == 0 ? "" : AccountAddress.fromString((pendingAdmin[0] as any).vec[0]);
  };

  publishPackage = async (filePath: string): Promise<string> => {
    return await this.buildAndPublishPackage(
      `${filePath}/${this.packageName}/`,
      this.packageDeployer,
      "aptos_extensions",
      [{ name: "deployer", address: this.packageDeployer.accountAddress.toString() }],
      new Uint8Array(Buffer.from("aptos_extensions")),
      "sparse"
    );
  };
}
