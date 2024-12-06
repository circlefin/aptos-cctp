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
