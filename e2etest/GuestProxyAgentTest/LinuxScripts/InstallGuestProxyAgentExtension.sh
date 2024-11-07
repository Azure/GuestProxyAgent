#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$devExtensionSas   

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Starting install guest proxy agent extension script" 
timeout=300
interval=5
elapsed=0
while :; do
    directories=$(find /var/lib/waagent -type d -name '*Microsoft.CPlat.ProxyAgent.ProxyAgentLinux*')
    found=0
    if [ $(echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $directories" | wc -l) -eq 1 ]; then
        for dir in $directories; do
            PIRExtensionFolderPath=$dir
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - PIR extension folder path=" $PIRExtensionFolderPath
            PIRExtensionFolderZip="${PIRExtensionFolderPath//-/__}.zip"
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - PIRExtensionFolderZip=$PIRExtensionFolderZip"
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
proxyAgentVersion="$(eval "$PIRExtensionFolderPath/ProxyAgent/ProxyAgent/azure-proxy-agent --version")"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - proxy agent version: $proxyAgentVersion"
statusFolder=$(find "$PIRExtensionFolderPath" -type d -name 'status')
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Status Directory: $statusFolder"

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Delete status file of PIR version" 
statusFile=$(ls $statusFolder/*.status)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - statusFile=$statusFile"
rm $statusFile

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
elapsed=0
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

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Check that status file is success with 5 minute timeout"
timeout=300
elapsed=0
if [[ "$statusExists" == "true" ]]; then
	while :; do 
    extensionStatus=$(cat "$statusFile" | jq -r '.[0].status.status')
    if [[ "$extensionStatus" == "success" ]]; then
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

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Check that process ProxyAgentExt is running"
processId=$(pgrep ProxyAgentExt)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - processId=$processId"
if [ -z "$processId" ]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Process ProxyAgentExt is not running"
else 
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Process ProxyAgentExt is running"
fi

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Delete PIR extension zip"
rm -rf $PIRExtensionFolderZip
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Delete PIR extension folder"
rm -rf $PIRExtensionFolderPath

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Downloading proxy agent extension binaries to PIR extension zip location"
decodedUrl=$(echo $zipFile | base64 -d)
curl -L -o $PIRExtensionFolderZip "$decodedUrl"

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Get PID of ProxyAgentExt and kill pidof"
pidof ProxyAgentExt | xargs kill -9

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Delete status file inside status folder"
rm -rf $statusFolder/*