#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$zipsas   # zipsas is a variable set by RunCommand extension by os.Setenv(name, value)

currentDir=$(pwd)
echo "currentDir=$currentDir"

echo "Starting guest proxy agent extension validation script" 
directories=$(find /var/lib/waagent -type d -name '*Microsoft.CPlat.ProxyAgent.ProxyAgentLinux*')
if [ $(echo "$directories" | wc -l) -eq 1 ]; then
    for dir in $directories; do 
        PIRExtensionFolderPath=$dir
        echo "PIR extension folder path" $PIRExtensionFolderPath
    done 
fi
extensionVersion=$(echo "$PIRExtensionFolderPath" | grep -oP '(\d+\.\d+\.\d+)$')
echo "extensionVersion=$extensionVersion"

echo "TEST: Check that status file is success with 5 minute timeout"
guestProxyAgentExtensionStatusObjGenerated=false
statusFile=$(ls $statusFolder/*.status)
timeout=300
elpased=0
while :; do 
    extensionStatus=$(cat "$statusFile" | jq -r '.[0].status.status')
    if [[ "$extensionStatus" == "Success" ]]; then
        guestProxyAgentExtensionStatusObjGenerated=true
        echo "The status is success."
        break
    fi
    ((elapsed += interval))
    if [[ $elapsed -ge $timeout ]]; then
        echo "Timeout reached. Exiting the loop."
        break
    fi
    sleep 5
done

echo "TEST: Check that process ProxyAgentExt is running"
processId=$(pgrep ProxyAgentExt)
echo "processId=$processId"
if [ -z "$processId" ]; then
    echo "Process ProxyAgentExt is not running"
    guestProxyAgentExtensionProcessExist=false
else 
    echo "Process ProxyAgentExt is running"
    guestProxyAgentExtensionProcessExist=true
fi

echo "TEST: Check that detailed status of the extension status to see if the key latch is successful"
proxyAgentstatus=$(cat "$statusFile" | jq -r '.[0].status.substatus[1].formattedMessage.message')
guestProxyAgentExtensionKeyLatchSuccessful=false
if [[ $proxyAgentstatus == *"ready to use"* ]]; then
    echo "Key latch is successful" 
    guestProxyAgentExtensionKeyLatchSuccessful=true
else
    echo "Key latch is not successful"
fi

echo "Create a json object with the variables guestProxyAgentExtensionStatusObjGenerated,
guestProxyAgentExtensionProcessExist, and guestProxyAgentExtensionKeyLatchSuccessful"
jsonObj="{\"guestProxyAgentExtensionStatusObjGenerated\":$guestProxyAgentExtensionStatusObjGenerated,
\"guestProxyAgentExtensionProcessExist\":$guestProxyAgentExtensionProcessExist,
\"guestProxyAgentExtensionKeyLatchSuccessful\":$guestProxyAgentExtensionKeyLatchSuccessful}"
echo "jsonObj=$jsonObj"
echo $jsonObj > ProxyAgentExtensionValidation.json