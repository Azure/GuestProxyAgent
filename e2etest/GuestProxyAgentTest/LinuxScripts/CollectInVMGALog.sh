#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

currentDir=$(pwd)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - currentDir=$currentDir"
zipFilePath=$currentDir/guest-proxy-agent-logs.zip
decodedLogZipSas=$(echo $logZipSas | base64 -d)

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - detecting os and installing zip" #TODO: needs to be revisited if we support other distros
os=$(hostnamectl | grep "Operating System")
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    for  i in {1..3}; do
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start installing zip via apt-get $i"
        sudo apt update
        sudo apt-get install zip
        sleep 10
        install=$(apt list --installed zip)
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - install=$install"
        if [[ $install == *"zip"* ]]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - zip installed successfully"
            break
        fi
    done
else
    for  i in {1..3}; do
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start installing zip via dnf $i"
        sudo dnf -y install zip
        sleep 10
        install=$(dnf list --installed zip)
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - install=$install"
        if [[ $install == *"zip"* ]]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $(date -u +"%Y-%m-%dT%H:%M:%SZ") - zip installed successfully"
            break
        fi
    done
fi

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - call zip -r $zipFilePath /var/log/azure-proxy-agent"
cd /var/log/azure-proxy-agent
zip -r $zipFilePath .
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - call zip -r $zipFilePath /var/log/azure"
cd /var/log/azure
zip -r $zipFilePath .
ls -l $currentDir

# upload log to blob
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start uploading file $zipFilePath to blob"
curl -X PUT -T $zipFilePath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$decodedLogZipSas"