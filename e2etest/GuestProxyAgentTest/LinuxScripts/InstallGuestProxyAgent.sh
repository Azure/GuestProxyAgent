#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$zipsas   # zipsas is a variable set by RunCommand extension by os.Setenv(name, value)

currentDir=$(pwd)
echo "currentDir=$currentDir"

echo "detecting os and installing unzip" #TODO: needs to be revisited if we support other distros
os=$(hostnamectl | grep "Operating System")
echo "os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    for  i in {1..3}; do
        echo "start installing unzip via apt-get $i"
        sudo apt update
        sudo apt-get install unzip
        sleep 10
        install=$(apt list --installed unzip)
        echo "install=$install"
        if [[ $install == *"unzip"* ]]; then
            echo "unzip installed successfully"
            break
        fi
    done
else
    for  i in {1..3}; do
        echo "start installing unzip via yum $i"
        sudo yum -y install unzip
        sleep 10
        install=$(yum list --installed unzip)
        echo "install=$install"
        if [[ $install == *"unzip"* ]]; then
            echo "unzip installed successfully"
            break
        fi
    done
fi

zipFilePath=$currentDir/guest-proxy-agent.zip
decodedUrl=$(echo $zipFile | base64 -d)
echo "start downloading guest-proxy-agent.zip"
curl -L -o $zipFilePath "$decodedUrl"

echo "start unzipping guest-proxy-agent.zip"
unzip -o $zipFilePath -d $currentDir
ls -l $currentDir

echo "start install & start guest-proxy-agent"
$currentDir/ProxyAgent/proxy_agent_setup install

