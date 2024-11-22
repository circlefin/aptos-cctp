/**
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  MoveOption,
  MoveString,
  MoveVector,
  Serializable,
  Serializer,
  U64,
  U8
} from "@aptos-labs/ts-sdk";

/**
 * Translated from https://github.com/aptos-labs/aptos-core/blob/f996f5855e54388f3d4f77e46b159b2498c850d4/aptos-move/framework/aptos-framework/sources/code.move#L67.
 */
class UpgradePolicy extends Serializable {
  private policy: U8;

  constructor(policy: U8) {
    super();
    this.policy = policy;
  }

  serialize(serializer: Serializer): void {
    serializer.serialize(this.policy);
  }
}

/**
 * Translated from https://github.com/aptos-labs/aptos-core/blob/f996f5855e54388f3d4f77e46b159b2498c850d4/aptos-move/framework/aptos-framework/sources/code.move#L27.
 */
class PackageMetadata extends Serializable {
  private name: MoveString;
  private upgrade_policy: UpgradePolicy;
  private upgrade_number: U64;
  private source_digest: MoveString;
  private manifest: MoveVector<U8>;
  private modules: MoveVector<any>;
  private deps: MoveVector<any>;
  private extension: MoveOption<any>;

  constructor(
    name: MoveString,
    upgrade_policy: UpgradePolicy,
    upgrade_number: U64,
    source_digest: MoveString,
    manifest: MoveVector<U8>,
    modules: MoveVector<any>,
    deps: MoveVector<any>,
    extension: MoveOption<any>
  ) {
    super();
    this.name = name;
    this.upgrade_policy = upgrade_policy;
    this.upgrade_number = upgrade_number;
    this.source_digest = source_digest;
    this.manifest = manifest;
    this.modules = modules;
    this.deps = deps;
    this.extension = extension;
  }

  serialize(serializer: Serializer): void {
    serializer.serialize(this.name);
    serializer.serialize(this.upgrade_policy);
    serializer.serialize(this.upgrade_number);
    serializer.serialize(this.source_digest);
    serializer.serialize(this.manifest);
    serializer.serialize(this.modules);
    serializer.serialize(this.deps);
    serializer.serialize(this.extension);
  }
}

async function main() {
  // BCS-serialize a default PackageMetadata.
  const packageMetadata = new PackageMetadata(
    new MoveString("test"),
    new UpgradePolicy(new U8(1)),
    new U64(0),
    new MoveString(""),
    new MoveVector([]),
    new MoveVector([]),
    new MoveVector([]),
    new MoveOption(null)
  );
  const serializer = new Serializer();
  serializer.serialize(packageMetadata);
  console.log("0x" + Buffer.from(serializer.toUint8Array()).toString("hex"));
}

main().catch(console.error);
