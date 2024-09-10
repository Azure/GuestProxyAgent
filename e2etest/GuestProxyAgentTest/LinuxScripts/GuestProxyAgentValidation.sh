#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

customOutputJsonUrl=$(echo $customOutputJsonSAS | base64 -d)

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Start Guest Proxy Agent Validation"
currentDir=$(pwd)
customOutputJsonPath=$currentDir/proxyagentvalidation.json

serviceName="azure-proxy-agent"
guestProxyAgentServiceExist=$(systemctl list-unit-files | grep $serviceName | wc -l)
guestProxyAgentServiceStatus="unknown"
if [ $guestProxyAgentServiceExist -eq 0 ]; then
    guestProxyAgentServiceExist='false'
    guestProxyAgentServiceStatus="service not exists"
else
    guestProxyAgentServiceExist='true'
    guestProxyAgentServiceStatus=$(systemctl is-enabled $serviceName)
fi
guestProxyProcessStarted=$(systemctl is-active $serviceName)
# check guestProxyProcessStarted is 'active'
if [ "$guestProxyProcessStarted" == "active" ]; then
    guestProxyProcessStarted='true'
else
    guestProxyProcessStarted=$(ps -C azure-proxy-agent)
    if [[ $guestProxyProcessStarted == *"azure-proxy-agent"* ]]; then
        guestProxyProcessStarted='true'
    else
        guestProxyProcessStarted='false'
    fi
fi

logdir="/var/log/azure-proxy-agent"
guestProxyAgentLogGenerated='false'
if [ -d "$logdir" ]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - logdir '$logdir' exists"
    ls -l $logdir
    # check if any log file is generated
    logFileCount=$(ls -l $logdir | grep -v ^l | wc -l)
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - logFileCount=$logFileCount"
    if [ $logFileCount -gt 0 ]; then
        guestProxyAgentLogGenerated='true'
    fi
else
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - logdir does not exist"
fi

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyAgentServiceExist=$guestProxyAgentServiceExist"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyAgentServiceStatus=$guestProxyAgentServiceStatus"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyProcessStarted=$guestProxyProcessStarted"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyAgentLogGenerated=$guestProxyAgentLogGenerated"

jsonString='{"guestProxyAgentServiceInstalled": "'$guestProxyAgentServiceExist'", "guestProxyAgentServiceStatus": "'$guestProxyAgentServiceStatus'", "guestProxyProcessStarted": "'$guestProxyProcessStarted'", "guestProxyAgentLogGenerated": "'$guestProxyAgentLogGenerated'"}'
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $jsonString"

# write to $customOutputJsonPath
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $jsonString" > $customOutputJsonPath

# upload $customOutputJsonPath to blob
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start uploading file=@$customOutputJsonPath to blob"
curl -X PUT -T $customOutputJsonPath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$customOutputJsonUrl"