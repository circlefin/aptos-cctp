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

docker stop local-testnet-postgres  && docker rm -f -v local-testnet-postgres || true
docker stop local-testnet-indexer-api  && docker rm -f -v local-testnet-indexer-api || true
docker stop anvil-eth && docker rm -f -v anvil-eth || true
docker volume rm local-testnet-postgres-data
