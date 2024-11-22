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

export enum MoveFunction {
  // MessageTransmitter
  InitializeMessageTransmitter = "initialize_message_transmitter",
  DisableAttester = "disable_attester",
  EnableAttester = "enable_attester",
  GetAttesterManager = "attester_manager",
  GetEnabledAttester = "get_enabled_attester",
  IsEnabledAttester = "is_enabled_attester",
  SetMaxMessageBodySize = "set_max_message_body_size",
  SetSignatureThreshold = "set_signature_threshold",
  UpdateAttesterManager = "update_attester_manager",

  // TokenMessengerMinter
  InitializeTokenMessengerMinter = "initialize_token_messenger_minter",
  AddRemoteTokenMessenger = "add_remote_token_messenger",
  GetRemoteTokenMessenger = "remote_token_messenger",
  GetTokenController = "get_token_controller",
  LinkTokenPair = "link_token_pair",
  SetMaxBurnAmountPerMessage = "set_max_burn_amount_per_message",
  SetTokenController = "set_token_controller",
  RemoveRemoteTokenMessenger = "remove_remote_token_messenger",
  UnlinkTokenPair = "unlink_token_pair",
  SignerAddress = "signer_address",

  // Ownable
  TransferOwnership = "transfer_ownership",
  AcceptOwnership = "accept_ownership",
  Owner = "owner",
  PendingOwner = "pending_owner",

  // Pausable
  Pause = "pause",
  Unpause = "unpause",
  UpdatePauser = "update_pauser",
  Pauser = "pauser",

  // Stablecoin
  InitializeV1 = "initialize_v1",
  ConfigureController = "configure_controller",
  ConfigureMinter = "configure_minter",
}