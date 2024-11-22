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

/** @type {import('ts-jest/dist/types').JestConfigWithTsJest} */

module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/e2e/test/*.test.[jt]s?(x)"],
  testPathIgnorePatterns: ["/node_modules/"],
  maxWorkers: 1,
  verbose: true,
  transform: {
    "^.+\\.ts?(x)$": ["ts-jest", { tsconfig: "tsconfig.json" }],
  },
};
