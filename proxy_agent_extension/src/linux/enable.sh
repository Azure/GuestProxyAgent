#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

script_dir="$(dirname "$(readlink -f "$0")")"
"$script_dir/ProxyAgentExt" enable
