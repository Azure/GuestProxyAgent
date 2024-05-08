#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

customOutputJsonUrl=$(echo $customOutputJsonSAS | base64 -d)

echo "Start Guest Proxy Agent Validation"
currentDir=$(pwd)
customOutputJsonPath=$currentDir/proxyagentvalidation.json

serviceName="GuestProxyAgent"
guestProxyAgentServiceExist=$(systemctl list-unit-files | grep $serviceName | wc -l)
guestProxyAgentServiceStatus="unknown"
if [ $guestProxyAgentServiceExist -eq 0 ]; then
    guestProxyAgentServiceExist='false'
    guestProxyAgentServiceStatus = "service not exists"
else
    guestProxyAgentServiceExist='true'
    guestProxyAgentServiceStatus=$(systemctl is-enabled $serviceName)
fi
guestProxyProcessStarted=$(systemctl is-active $serviceName)
# check guestProxyProcessStarted is 'active'
if [ "$guestProxyProcessStarted" == "active" ]; then
    guestProxyProcessStarted='true'
else
    guestProxyProcessStarted=$(ps -C GuestProxyAgent)
    if [[ $guestProxyProcessStarted == *"GuestProxyAgent"* ]]; then
        guestProxyProcessStarted='true'
    else
        guestProxyProcessStarted='false'
    fi
fi

logdir="/var/log/azure-proxy-agent"
guestProxyAgentLogGenerated='false'
if [ -d "$logdir" ]; then
    echo "logdir '$logdir' exists"
    ls -l $logdir
    # chck if any log file is generated
    logFileCount=$(ls -l $logdir | grep -v ^l | wc -l)
    echo "logFileCount=$logFileCount"
    if [ $logFileCount -gt 0 ]; then
        guestProxyAgentLogGenerated='true'
    fi
else
    echo "logdir does not exist"
fi

echo "guestProxyAgentServiceExist=$guestProxyAgentServiceExist"
echo "guestProxyAgentServiceStatus=$guestProxyAgentServiceStatus"
echo "guestProxyProcessStarted=$guestProxyProcessStarted"
echo "guestProxyAgentLogGenerated=$guestProxyAgentLogGenerated"

jsonString='{"guestProxyAgentServiceInstalled": "'$guestProxyAgentServiceExist'", "guestProxyAgentServiceStatus": "'$guestProxyAgentServiceStatus'", "guestProxyProcessStarted": "'$guestProxyProcessStarted'", "guestProxyAgentLogGenerated": "'$guestProxyAgentLogGenerated'"}'
echo "$jsonString"

# write to $customOutputJsonPath
echo "$jsonString" > $customOutputJsonPath

# upload $customOutputJsonPath to blob
echo "start uploading file=@$customOutputJsonPath to blob"
curl -X PUT -T $customOutputJsonPath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$customOutputJsonUrl"