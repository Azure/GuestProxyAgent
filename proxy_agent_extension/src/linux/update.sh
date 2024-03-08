#!/bin/bash
script_dir="$(dirname "$(readlink -f "$0")")"
"$script_dir/ProxyAgentExt" update
