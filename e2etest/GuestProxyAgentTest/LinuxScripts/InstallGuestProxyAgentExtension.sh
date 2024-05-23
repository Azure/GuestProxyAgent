#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$zipsas   # zipsas is a variable set by RunCommand extension by os.Setenv(name, value)

currentDir=$(pwd)
echo "currentDir=$currentDir"

echo "Starting install guest proxy agent extension script" 

# find extension version from /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-1.0.11

extensionVersion=$(ls /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-*)
PIRExtensionFolderPath=$(ls /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-*/)
echo "extensionVersion=$extensionVersion"

# Get status file from /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-1.0.11/status

statusFolder=$(ls /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-*/status)

echo "statusFolder=$statusFolder"

echo "Delete status file of PIR version" 

# delete status file inside status folder

rm -f $statusFolder/*

echo "Check that status file is success with 5 minute timeout"

# get status file from status folder ending in .status

statusFile=$(ls $statusFolder/*.status)

# check status file for success by converting to json and checking status.status field, in a loop with 5 minute timeout and echo if status is not success or reached timeout

timeout 5m bash -c 'until [[ $(cat $statusFile | jq -r .status) == "success" ]]; do sleep 10; done' || echo "Status file is not success or reached timeout"

# check that process ProxyAgentExt is running 

echo "Check that process ProxyAgentExt is running"

# get process id of ProxyAgentExt

processId=$(pgrep ProxyAgentExt)

echo "processId=$processId"

# check that process id is not empty

if [ -z "$processId" ]; then
    echo "Process ProxyAgentExt is not running"
fi
else 
    echo "Process ProxyAgentExt is running"

# delete PIR extension folder

echo "Delete PIR extension folder"

rm -rf $PIRExtensionFolderPath

# get PID of ProxyAgentExt and kill pidof

echo "Get PID of ProxyAgentExt and kill pidof"

pidof ProxyAgentExt | xargs kill -9

# delete status file inside status folder

echo "Delete status file inside status folder"

rm -f $statusFolder/*