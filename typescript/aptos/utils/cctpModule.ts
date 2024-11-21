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

export enum MoveModule {
  Attester = "attester",
  MessageTransmitter = "message_transmitter",
  TokenMessenger = "token_messenger",
  TokenMessengerMinter = "token_messenger_minter",
  TokenController = "token_controller",
  Stablecoin = "stablecoin",
  Treasury = "treasury",

  // Aptos Extensions
  Pausable = "pausable",
  Ownable = "ownable",
}
