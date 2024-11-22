#!/usr/bin/env bash
# Copyright (c) 2024, Circle Internet Group, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


start_aptos_localnet() {
    # Create logs directory and aptos.log file if they don't exist
    mkdir -p logs
    touch logs/aptos.log

    echo "Starting aptos localnet"
    aptos node run-localnet \
        --with-indexer-api \
        --force-restart \
        --assume-yes \
        --test-dir ~/.aptos/testnet \
        >logs/aptos.log 2>&1 & # the startup output holds the shell so we redirect to a file and send to the background.

    until curl -s localhost:8070 | jq '.not_ready | length == 0'
    do
        sleep 2
    done

    echo "Successfully started Aptos localnet!"
}
