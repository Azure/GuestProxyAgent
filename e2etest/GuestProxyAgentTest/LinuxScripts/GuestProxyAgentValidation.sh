#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

customOutputJsonUrl=$(echo $customOutputJsonSAS | base64 -d)
expectedSecureChannelState=$(echo $expectedSecureChannelState)

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Start Guest Proxy Agent Validation"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - expectedSecureChannelState=$expectedSecureChannelState"

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

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - detecting os and installing jq" 
os=$(hostnamectl | grep "Operating System")
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    for  i in {1..3}; do
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start installing jq via apt-get $i"
        sudo apt update
        sudo apt-get install -y jq
        sleep 10
        install=$(apt list --installed jq)
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - install=$install"
        if [[ $install == *"jq"* ]]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - jq installed successfully"
            break
        fi
    done
else
    for  i in {1..3}; do
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start installing jq via dnf $i"
        sudo dnf -y install jq
        sleep 10
        install=$(dnf list --installed jq)
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - install=$install"
        if [[ $install == *"jq"* ]]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - jq installed successfully"
            break
        fi
    done
fi

# check status.json file Content
## check timestamp of last entry in status.json file
## check the secure channel status
timeout=300
elapsed=0
statusFile=$logdir/status.json
secureChannelState=""

# Current UTC time in epoch seconds
currentUtcTime=$(date -u +%s)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Checking GPA status file $statusFile with 5 minute timeout"
while :; do 
    timestamp=$(cat "$statusFile" | jq -r '.timestamp')
    # Convert timestamp to epoch seconds
    timestampEpoch=$(date -u -d "$timestamp" +%s)
    if ((timestampEpoch > currentUtcTime)); then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - The last entry timestamp '$timestamp' is valid."
        ## check secure channel status
        secureChannelState=$(cat "$statusFile" | jq -r '.proxyAgentStatus.keyLatchStatus.states.secureChannelState')
        if [[ "$secureChannelState" == "$expectedSecureChannelState" ]]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - The secure channel status '$secureChannelState' matches the expected state: '$expectedSecureChannelState'."
            break
        else
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - The secure channel status '$secureChannelState' does not match the expected state: '$expectedSecureChannelState'."
        fi
    fi
    ((elapsed += 3))
    if [[ $elapsed -ge $timeout ]]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Timeout reached. Error, The secureChannelState is '$secureChannelState'."
        break
    fi
    sleep 3
done

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyAgentServiceExist=$guestProxyAgentServiceExist"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyAgentServiceStatus=$guestProxyAgentServiceStatus"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyProcessStarted=$guestProxyProcessStarted"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - guestProxyAgentLogGenerated=$guestProxyAgentLogGenerated"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - secureChannelState=$secureChannelState"

jsonString='{"guestProxyAgentServiceInstalled": "'$guestProxyAgentServiceExist'", "guestProxyAgentServiceStatus": "'$guestProxyAgentServiceStatus'", "guestProxyProcessStarted": "'$guestProxyProcessStarted'", "secureChannelState": "'$secureChannelState'", "guestProxyAgentLogGenerated": "'$guestProxyAgentLogGenerated'"}'
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $jsonString"

# write to $customOutputJsonPath
echo "$jsonString" > $customOutputJsonPath

# upload $customOutputJsonPath to blob
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start uploading file=@$customOutputJsonPath to blob"
curl -X PUT -T $customOutputJsonPath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$customOutputJsonUrl"