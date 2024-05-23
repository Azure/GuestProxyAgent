#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$zipsas   # zipsas is a variable set by RunCommand extension by os.Setenv(name, value)

currentDir=$(pwd)
echo "currentDir=$currentDir"

echo "Starting guest proxy agent extension validation script" 

# find extension version from /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-1.0.11

extensionVersion=$(ls /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-*)

echo "extensionVersion=$extensionVersion"

# get status file and check that it is success with 5 minute timeout

statusFolder=$(ls /var/lib/waagent/Microsoft.CPlat.ProxyAgent.ProxyAgentLinuxTest-*/status)

echo "statusFolder=$statusFolder"

echo "Check that status file is success with 5 minute timeout"

statusFile=$(ls $statusFolder/*.status)

# if status is success during timeout set variable guestProxyAgentExtensionStatusObjGenerated to true else set to false

guestProxyAgentExtensionStatusObjGenerated=false

timeout 5m bash -c 'until [[ $(cat $statusFile | jq -r .status) == "success" ]]; do sleep 10; done && guestProxyAgentExtensionStatusObjGenerated=true' || echo "Status file is not success or reached timeout"

# check that process ProxyAgentExt is running and set varaible guestProxyAgentExtensionProcessExist to true 

echo "Check that process ProxyAgentExt is running"

processId=$(pgrep ProxyAgentExt)

echo "processId=$processId"

if [ -z "$processId" ]; then
    echo "Process ProxyAgentExt is not running"
    guestProxyAgentExtensionProcessExist=false
else 
    echo "Process ProxyAgentExt is running"
    guestProxyAgentExtensionProcessExist=true
fi

# check the detailed status of the extension status to see if the key latch is successful 

echo "Check that detailed status of the extension status to see if the key latch is successful"

# get detailed status file from status file by converting to json and checking the status.substatus[1].formattedMessage.message field 

proxyAgentstatus=$(cat $statusFile | jq -r .status.substatus[1].formattedMessage.message)

# if key latch is successful set variable guestProxyAgentExtensionKeyLatchSuccessful to true else set to false

guestProxyAgentExtensionKeyLatchSuccessful=false

# if "ready to use" is in the proxyAgentstatus set guestProxyAgentExtensionKeyLatchSuccessful to true

if [[ $proxyAgentstatus == *"ready to use"* ]]; then
    guestProxyAgentExtensionKeyLatchSuccessful=true
else
    echo "Key latch is not successful"
fi

# create a json object with the variables guestProxyAgentExtensionStatusObjGenerated, guestProxyAgentExtensionProcessExist, and guestProxyAgentExtensionKeyLatchSuccessful

echo "Create a json object with the variables guestProxyAgentExtensionStatusObjGenerated, guestProxyAgentExtensionProcessExist, and guestProxyAgentExtensionKeyLatchSuccessful"

jsonObj="{\"guestProxyAgentExtensionStatusObjGenerated\":$guestProxyAgentExtensionStatusObjGenerated,\"guestProxyAgentExtensionProcessExist\":$guestProxyAgentExtensionProcessExist,\"guestProxyAgentExtensionKeyLatchSuccessful\":$guestProxyAgentExtensionKeyLatchSuccessful}"

echo "jsonObj=$jsonObj"

# write the json object to a file ProxyAgentExtensionValidation.json in the current directory

echo $jsonObj > ProxyAgentExtensionValidation.json