#!/usr/bin/env bash
#
# Copyright (c) 2024, Circle Internet Group, Inc.
# All rights reserved.
#
# Circle Internet Group, Inc. CONFIDENTIAL
#
# This file includes unpublished proprietary source code of Circle Internet
# Group, Inc. The copyright notice above does not evidence any actual or
# intended publication of such source code. Disclosure of this source code
# or any related proprietary information is strictly prohibited without
# the express written permission of Circle Internet Group, Inc.
#

OUTPUT_DIR="container-logs"
mkdir -p ${OUTPUT_DIR}
CONTAINERS=$(docker ps --format '{{.Names}}')
echo "found containers: ${CONTAINERS}"
for CONTAINER in ${CONTAINERS}; do
    docker logs ${CONTAINER} >& ${OUTPUT_DIR}/${CONTAINER}.log
done

echo "Successfully exported logs in ${OUTPUT_DIR} directory."
