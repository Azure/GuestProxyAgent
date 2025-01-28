#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$zipsas   # zipsas is a variable set by RunCommand extension by os.Setenv(name, value)

currentDir=$(pwd)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - currentDir=$currentDir"

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - detecting os and installing unzip" #TODO: needs to be revisited if we support other distros
os=$(hostnamectl | grep "Operating System")
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    for  i in {1..3}; do
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start installing unzip via apt-get $i"
        sudo apt-get update
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - apt-get install unzip"
        sudo apt-get install unzip
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - apt-get install unzip with exit code=$?"
        sleep 10
        install=$(apt list --installed unzip)
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - install=$install"
        if [[ $install == *"unzip"* ]]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - unzip installed successfully"
            break
        fi
    done
else
    for  i in {1..3}; do
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start installing unzip via dnf $i"
        sudo dnf -y install unzip
        sleep 10
        install=$(dnf list --installed unzip)
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - install=$install"
        if [[ $install == *"unzip"* ]]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - unzip installed successfully"
            break
        fi
    done
fi

zipFilePath=$currentDir/guest-proxy-agent.zip
decodedUrl=$(echo $zipFile | base64 -d)
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start downloading guest-proxy-agent.zip"
curl -L -o $zipFilePath "$decodedUrl"

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start unzipping guest-proxy-agent.zip"
unzip -o $zipFilePath -d $currentDir
ls -l $currentDir

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - start install & start guest-proxy-agent"
$currentDir/ProxyAgent/proxy_agent_setup install

