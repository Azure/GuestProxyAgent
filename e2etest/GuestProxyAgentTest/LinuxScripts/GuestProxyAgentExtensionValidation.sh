#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

customOutputJsonUrl=$(echo $customOutputJsonSAS | base64 -d)
expectedProxyAgentVersion=$(echo $expectedProxyAgentVersion)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - expectedProxyAgentVersion=$expectedProxyAgentVersion"
currentDir=$(pwd)
customOutputJsonPath=$currentDir/proxyagentextensionvalidation.json

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Starting guest proxy agent extension validation script" 

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Get Extension Folder and Version"
timeout=300
interval=5
elpased=0
while :; do
    directories=$(find /var/lib/waagent -type d -name '*Microsoft.CPlat.ProxyAgent.ProxyAgentLinux*')
    found=0
    if [ $(echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $directories" | wc -l) -eq 1 ]; then
        for dir in $directories; do
            PIRExtensionFolderPath=$dir
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - PIR extension folder path=" $PIRExtensionFolderPath
            found=1
        done
        if [ $found -eq 1 ]; then
            break
        fi
    fi
    ((elapsed += interval))
    if [[ $elapsed -ge $timeout ]]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Timeout reached. Exiting the loop."
        break
    fi
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Waiting for the extension folder to be created: $elapsed seconds elapsed"
    sleep $interval
done
PIRExtensionVersion=$(echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $PIRExtensionFolderPath" | grep -oP '(\d+\.\d+\.\d+)$')
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - PIRExtensionVersion=$PIRExtensionVersion"

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

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Check that status file is regenerated"
timeout=900
elpased=0
while :; do 
    statusFolder=$(find "$PIRExtensionFolderPath" -type d -name 'status')
	statusFile=$(ls $statusFolder/*.status)
	if [ -f "$statusFile" ]; then
		echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - statusFile=$statusFile"
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Contents of status file:"
        cat "$statusFile"
        statusExists=true
		break
    fi
    ((elapsed += 5))
    if [[ $elapsed -ge $timeout ]]; then
		echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Timeout reached. Exiting the loop, status file is not regenerated."
        statusExists=false
		break
    fi
	sleep 5
done

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - TEST: Check that status file is success with 5 minute timeout"
guestProxyAgentExtensionStatusObjGenerated=false
guestProxyAgentExtensionServiceStatus=false
timeout=300
elpased=0
if [[ "$statusExists" == "true" ]]; then
	while :; do 
    extensionStatus=$(cat "$statusFile" | jq -r '.[0].status.status')
    if [[ "$extensionStatus" == "success" ]]; then
        guestProxyAgentExtensionStatusObjGenerated=true
        guestProxyAgentExtensionServiceStatus=true
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - The status is success."
        break
    fi
    ((elapsed += 5))
    if [[ $elapsed -ge $timeout ]]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Timeout reached. Exiting the loop."
        break
    fi
    sleep 5
done
fi

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - TEST: Check that process ProxyAgentExt is running"
processId=$(pgrep ProxyAgentExt)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - processId=$processId"
if [ -z "$processId" ]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Process ProxyAgentExt is not running"
    guestProxyAgentExtensionServiceExist=false
    guestProxyAgentExtensionProcessExist=false
else 
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Process ProxyAgentExt is running"
    guestProxyAgentExtensionServiceExist=true
    guestProxyAgentExtensionProcessExist=true
fi

echo Write-Output "TEST: ProxyAgent version running in VM is the same as expected version" 
proxyAgentVersion="$(eval "$PIRExtensionFolderPath/ProxyAgent/ProxyAgent/azure-proxy-agent --version")"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - proxy agent version from extension folder: $proxyAgentVersion"
guestProxyAgentExtensionVersion=true
proxyAgentStatus=$(cat "$statusFile" | jq -r '.[0].status.substatus[1].formattedMessage.message')
extractedVersion=$(echo $proxyAgentStatus | jq -r '.version')
if [[ $proxyAgentVersion == $extractedVersion ]]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - ProxyAgent version running in VM is the same as expected version"
else
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - ProxyAgent version [$proxyAgentVersion] running in VM is not the same as expected version [$extractedVersion]"
    guestProxyAgentExtensionVersion=false
fi
if [ $expectedProxyAgentVersion != "0" ]; then
    if [[ $proxyAgentVersion == $expectedProxyAgentVersion ]]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - After Update Version check: ProxyAgent version running in VM is the same as expected and extracted version"
    else
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - After Update Version check: ProxyAgent version [$proxyAgentVersion] running in VM is not the same as expected version [$expectedProxyAgentVersion]"
        guestProxyAgentExtensionVersion=false
    fi
fi

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - TEST: Check that detailed status of the extension status to see if the Instance View is successful"
guestProxyAgentExtensionInstanceView=false
if [[ $proxyAgentStatus == *"SUCCESS"* ]]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Instance View is successful" 
    guestProxyAgentExtensionInstanceView=true
else
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Instance View is not successful"
fi

jsonString='{"guestProxyAgentExtensionStatusObjGenerated": "'$guestProxyAgentExtensionStatusObjGenerated'", "guestProxyAgentExtensionProcessExist": "'$guestProxyAgentExtensionProcessExist'", "guestProxyAgentExtensionServiceExist": "'$guestProxyAgentExtensionServiceExist'", "guestProxyAgentExtensionVersion": "'$guestProxyAgentExtensionVersion'", "guestProxyAgentExtensionInstanceView": "'$guestProxyAgentExtensionInstanceView'", "guestProxyAgentExtensionServiceStatus": "'$guestProxyAgentExtensionServiceStatus'"}'
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $jsonString"

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $jsonString" > $customOutputJsonPath
curl -X PUT -T $customOutputJsonPath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$customOutputJsonUrl"