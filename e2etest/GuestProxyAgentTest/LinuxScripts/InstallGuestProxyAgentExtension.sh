#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$zipsas   # zipsas is a variable set by RunCommand extension by os.Setenv(name, value)

currentDir=$(pwd)
echo "currentDir=$currentDir"

echo "Starting install guest proxy agent extension script" 

#$directories=find /var/lib/waagent -type d -name '*Microsoft.CPlat.ProxyAgent.ProxyAgentLinux*'

directories=$(find /var/lib/waagent -type d -name '*Microsoft.test.extension*')

if [ $(echo "$directories" | wc -l) -eq 1 ]; then
    for dir in $directories; do 
        PIRExtensionFolderPath=$dir
        echo "PIR extension folder path" $PIRExtensionFolderPath
    done 
fi

extensionVersion=$(echo "$PIRExtensionFolderPath" | grep -oP '(\d+\.\d+\.\d+)$')

echo "extensionVersion=$extensionVersion"

statusFolder=$(find "$PIRExtensionFolderPath" -type d -name 'status')
echo "Status Directory: $statusFolder"

echo "Delete status file of PIR version" 

# delete status file inside status folder

rm -f $statusFolder/*

echo "Check that status file is success with 5 minute timeout"

# get status file from status folder ending in .status

statusFile=$(ls $statusFolder/*.status)

# Set the timeout duration to 5 minutes
timeout_duration="5m"

# Command to check the status
check_status_cmd="jq -r '.[0].status.status' $statusFile"

# Use the timeout command to run the check_status_cmd
# If the command times out, it will exit with status 124
if output=$(timeout $timeout_duration bash -c "$check_status_cmd"); then
  # If the command didn't time out, check the status
  if [ "$output" == "Success" ]; then
    echo "The status is success."
  else
    echo "The status is not success."
  fi
else
  # If the timeout command exited with status 124, it timed out
  if [ $? -eq 124 ]; then
    echo "The command timed out."
  fi
fi

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