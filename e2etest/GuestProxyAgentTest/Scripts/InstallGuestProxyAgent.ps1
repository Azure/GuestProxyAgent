# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$zipsas
)

$currentFolder = $PWD.Path
$zipFilePath =  Join-Path -Path $currentFolder -ChildPath "GuestProxyAgent.zip"

$decodedUrlBytes = [System.Convert]::FromBase64String($zipsas)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

Write-Output "start downloading zip file path from blob: decodedUrlString" 
wget $decodedUrlString -OutFile $zipFilePath

$unzipFolder = Join-Path -Path $currentFolder -ChildPath "GuestProxyAgent"
Write-Output "unzip to folder: $unzipFolder"
Expand-Archive $zipFilePath -DestinationPath $unzipFolder

$msiFilePath = Get-ChildItem -Path $unzipFolder -Filter "*.msi"
$msiFileFullPath = $msiFilePath.FullName
Write-Output "installing/updating guest proxy agent, msi file path: $msiFileFullPath" 
Start-Process -FilePath $msiFileFullPath -Wait