#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - checking cgroup2 ... "
mount_cgroup2=$(mount | grep cgroup2)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - mount_cgroup2=$mount_cgroup2"

if [[ $mount_cgroup2 == *"cgroup2"* ]]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - cgroup2 is already mounted"
else
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - mount cgroup2 by default during system boot"
    sudo grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=1"
fi

