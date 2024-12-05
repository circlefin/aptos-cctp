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

export enum CctpFunctionScript {
  // MessageTransmitter
  InitMessageTransmitter = "init_message_transmitter",
  ReceiveMessage = "receive_message",
  ReplaceMessage = "replace_message",
  SendMessage = "send_message",
  SendMessageWithCaller = "send_message_with_caller",

  // TokenMessengerMinter
  InitTokenMessengerMinter = "init_token_messenger_minter",
  DepositForBurn = "deposit_for_burn",
  DepositForBurnWithCaller = "deposit_for_burn_with_caller",
  HandleReceiveMessage = "handle_receive_message",
  ReplaceDepositForBurn = "replace_deposit_for_burn",
  Mint = "mint",
}
