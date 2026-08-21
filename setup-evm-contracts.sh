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

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FOUNDRY_PATH="${FOUNDRY_PATH:-${HOME}/.config/.foundry/bin}"
FORGE="${FOUNDRY_PATH}/forge"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

if [[ ! -x "${FORGE}" ]]; then
  echo "Foundry forge was not found at ${FORGE}. Install the pinned version from the repository prerequisites before running this script." >&2
  exit 1
fi

required_variables=(
  RPC_URL_ETH
  SENDER
  MESSAGE_TRANSMITTER_DEPLOYER_KEY
  TOKEN_MESSENGER_DEPLOYER_KEY
  TOKEN_MINTER_DEPLOYER_KEY
  TOKEN_CONTROLLER_DEPLOYER_KEY
  ATTESTER_ADDRESS
  USDC_CONTRACT_ADDRESS
  TOKEN_CONTROLLER_ADDRESS
  BURN_LIMIT_PER_MESSAGE
  REMOTE_TOKEN_MESSENGER_ADDRESS
  REMOTE_USDC_CONTRACT_ADDRESS
  MESSAGE_TRANSMITTER_PAUSER_ADDRESS
  TOKEN_MINTER_PAUSER_ADDRESS
  MESSAGE_TRANSMITTER_RESCUER_ADDRESS
  TOKEN_MESSENGER_RESCUER_ADDRESS
  TOKEN_MINTER_RESCUER_ADDRESS
  MASTER_MINTER_ADDRESS
  TOKEN_MINTER_ADDRESS
  DUMMY_ADDRESS
  MASTER_MINTER_KEY
  UPGRADEABLE_KEY
  UPGRADEABLE_ADDRESS
)

for variable_name in "${required_variables[@]}"; do
  if [[ -z "${!variable_name:-}" ]]; then
    echo "Missing required environment variable: ${variable_name}" >&2
    exit 1
  fi
  export "${variable_name}"
done

export DOMAIN="${DOMAIN:-0}"

echo "Deploying evm-cctp-contracts contracts"

cd "${ROOT_DIR}"

# Update submodules.
git submodule update --init --recursive

# Install any needed dependency.
yarn install

cd "${ROOT_DIR}/evm-cctp-contracts"

# Build the Anvil image.
docker build --no-cache -f Dockerfile -t foundry .

# Create the Anvil container.
docker stop anvil-eth && docker rm anvil-eth || true
docker run -d -p 8500:8545 --name anvil-eth --rm foundry "anvil --host 0.0.0.0 -a 13 --code-size-limit 250000"

sleep 10

# Deploy the contracts.
"${FORGE}" script ../scripts/evm/cctp_deploy.s.sol:DeployScript --rpc-url "${RPC_URL_ETH}" --sender "${SENDER}" --broadcast
mkdir -p cctp-interfaces
cp -R ./out/* ./cctp-interfaces
"${FORGE}" script ../scripts/evm/usdc_deploy.s.sol:USDCDeployScript --rpc-url "${RPC_URL_ETH}" --sender "${SENDER}" --broadcast --force --use 0.6.12
mkdir -p usdc-interfaces
cp -R ./out/* ./usdc-interfaces
