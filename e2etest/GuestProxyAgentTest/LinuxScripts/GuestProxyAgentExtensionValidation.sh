#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

customOutputJsonUrl=$(echo $customOutputJsonSAS | base64 -d)
expectedProxyAgentVersion=$(echo $expectedProxyAgentVersion)
echo "expectedProxyAgentVersion=$expectedProxyAgentVersion"
currentDir=$(pwd)
customOutputJsonPath=$currentDir/proxyagentextensionvalidation.json

echo "Starting guest proxy agent extension validation script" 

echo "Get Extension Folder and Version"
timeout=300
elpased=0
while :; do
    directories=$(find /var/lib/waagent -type d -name '*Microsoft.CPlat.ProxyAgent.ProxyAgentLinux*')
    if [ $(echo "$directories" | wc -l) -eq 1 ]; then
        for dir in $directories; do 
            PIRExtensionFolderPath=$dir
            echo "PIR extension folder path=" $PIRExtensionFolderPath
        done 
        break
    fi
    ((elapsed += interval))
    if [[ $elapsed -ge $timeout ]]; then
        echo "Timeout reached. Exiting the loop."
        break
    fi
    sleep 5
done 
PIRExtensionVersion=$(echo "$PIRExtensionFolderPath" | grep -oP '(\d+\.\d+\.\d+)$')
echo "PIRExtensionVersion=$PIRExtensionVersion"

echo "detecting os and installing jq" 
os=$(hostnamectl | grep "Operating System")
echo "os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    for  i in {1..3}; do
        echo "start installing jq via apt-get $i"
        sudo apt update
        sudo apt-get install -y jq
        sleep 10
        install=$(apt list --installed jq)
        echo "install=$install"
        if [[ $install == *"jq"* ]]; then
            echo "jq installed successfully"
            break
        fi
    done
else
    for  i in {1..3}; do
        echo "start installing jq via yum $i"
        sudo yum -y install jq
        sleep 10
        install=$(yum list --installed jq)
        echo "install=$install"
        if [[ $install == *"jq"* ]]; then
            echo "jq installed successfully"
            break
        fi
    done
fi

echo "Check that status file is regenerated"
timeout=900
elpased=0
while :; do 
    statusFolder=$(find "$PIRExtensionFolderPath" -type d -name 'status')
	statusFile=$(ls $statusFolder/*.status)
	if [ -f "$statusFile" ]; then
		echo "statusFile=$statusFile"
        echo "Contents of status file:"
        cat "$statusFile"
        statusExists=true
		break
    fi
    ((elapsed += 5))
    if [[ $elapsed -ge $timeout ]]; then
		echo "Timeout reached. Exiting the loop, status file is not regenerated."
        statusExists=false
		break
    fi
	sleep 5
done

echo "TEST: Check that status file is success with 5 minute timeout"
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
        echo "The status is success."
        break
    fi
    ((elapsed += 5))
    if [[ $elapsed -ge $timeout ]]; then
        echo "Timeout reached. Exiting the loop."
        break
    fi
    sleep 5
done
fi

echo "TEST: Check that process ProxyAgentExt is running"
processId=$(pgrep ProxyAgentExt)
echo "processId=$processId"
if [ -z "$processId" ]; then
    echo "Process ProxyAgentExt is not running"
    guestProxyAgentExtensionServiceExist=false
    guestProxyAgentExtensionProcessExist=false
else 
    echo "Process ProxyAgentExt is running"
    guestProxyAgentExtensionServiceExist=true
    guestProxyAgentExtensionProcessExist=true
fi

echo Write-Output "TEST: ProxyAgent version running in VM is the same as expected version" 
proxyAgentVersion="$(eval "$PIRExtensionFolderPath/ProxyAgent/ProxyAgent/azure-proxy-agent --version")"
echo "proxy agent version from extension folder: $proxyAgentVersion"
guestProxyAgentExtensionVersion=true
proxyAgentStatus=$(cat "$statusFile" | jq -r '.[0].status.substatus[1].formattedMessage.message')
extractedVersion=$(echo $proxyAgentStatus | jq -r '.version')
if [[ $proxyAgentVersion == $extractedVersion ]]; then
    echo "ProxyAgent version running in VM is the same as expected version"
else
    echo "ProxyAgent version [$proxyAgentVersion] running in VM is not the same as expected version [$extractedVersion]"
    guestProxyAgentExtensionVersion=false
fi
if [ $expectedProxyAgentVersion != "0" ]; then
    if [[ $proxyAgentVersion == $expectedProxyAgentVersion ]]; then
        echo "After Update Version check: ProxyAgent version running in VM is the same as expected and extracted version"
    else
        echo "After Update Version check: ProxyAgent version [$proxyAgentVersion] running in VM is not the same as expected version [$expectedProxyAgentVersion]"
        guestProxyAgentExtensionVersion=false
    fi
fi

echo "TEST: Check that detailed status of the extension status to see if the Instance View is successful"
guestProxyAgentExtensionInstanceView=false
if [[ $proxyAgentStatus == *"SUCCESS"* ]]; then
    echo "Instance View is successful" 
    guestProxyAgentExtensionInstanceView=true
else
    echo "Instance View is not successful"
fi

jsonString='{"guestProxyAgentExtensionStatusObjGenerated": "'$guestProxyAgentExtensionStatusObjGenerated'", "guestProxyAgentExtensionProcessExist": "'$guestProxyAgentExtensionProcessExist'", "guestProxyAgentExtensionServiceExist": "'$guestProxyAgentExtensionServiceExist'", "guestProxyAgentExtensionVersion": "'$guestProxyAgentExtensionVersion'", "guestProxyAgentExtensionInstanceView": "'$guestProxyAgentExtensionInstanceView'", "guestProxyAgentExtensionServiceStatus": "'$guestProxyAgentExtensionServiceStatus'"}'
echo "$jsonString"

echo "$jsonString" > $customOutputJsonPath
curl -X PUT -T $customOutputJsonPath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$customOutputJsonUrl"