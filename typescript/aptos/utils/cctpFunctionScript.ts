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
