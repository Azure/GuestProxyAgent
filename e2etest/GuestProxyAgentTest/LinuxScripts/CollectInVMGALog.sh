#!/bin/bash
#logZipSas=$logZipSas

currentDir=$(pwd)
echo "currentDir=$currentDir"
zipFilePath=$currentDir/guest-proxy-agent-logs.zip
decodedLogZipSas=$(echo $logZipSas | base64 -d)

echo "detecting os and installing zip" #TODO: needs to be revisited if we support other distros
os=$(hostnamectl | grep "Operating System")
echo "os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    echo "start installing zip via apt-get"
    sudo apt update
    sudo apt-get install zip
else
    echo "start installing zip via yum"
    sudo yum -y install zip
fi

echo "call zip -r $zipFilePath /var/log/azure-proxy-agent"
cd /var/log/azure-proxy-agent
zip -r $zipFilePath .
ls -l $currentDir

# upload log to blob
echo "start uploading file $zipFilePath to blob"
curl -X PUT -T $zipFilePath -H "x-ms-date: $(date -u)" -H "x-ms-blob-type: BlockBlob" "$decodedLogZipSas"