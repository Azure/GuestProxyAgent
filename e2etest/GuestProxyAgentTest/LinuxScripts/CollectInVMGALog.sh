#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

currentDir=$(pwd)
echo "currentDir=$currentDir"
zipFilePath=$currentDir/guest-proxy-agent-logs.zip
decodedLogZipSas=$(echo $logZipSas | base64 -d)

echo "detecting os and installing zip" #TODO: needs to be revisited if we support other distros
os=$(hostnamectl | grep "Operating System")
echo "os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    for  i in {1..3}; do
        echo "start installing zip via apt-get $i"
        sudo apt update
        sudo apt-get install zip
        sleep 10
        install=$(apt list --installed zip)
        echo "install=$install"
        if [[ $install == *"zip"* ]]; then
            echo "zip installed successfully"
            break
        fi
    done
else
    for  i in {1..3}; do
        echo "start installing zip via yum $i"
        sudo yum -y install zip
        sleep 10
        install=$(yum list --installed zip)
        echo "install=$install"
        if [[ $install == *"zip"* ]]; then
            echo "zip installed successfully"
            break
        fi
    done
fi

echo "call zip -r $zipFilePath /var/log/azure-proxy-agent"
cd /var/log/azure-proxy-agent
zip -r $zipFilePath .
ls -l $currentDir

# upload log to blob
echo "start uploading file $zipFilePath to blob"
curl -X PUT -T $zipFilePath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$decodedLogZipSas"