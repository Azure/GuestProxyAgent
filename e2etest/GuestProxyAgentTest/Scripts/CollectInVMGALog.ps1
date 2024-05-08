# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$logZipSas
)

$decodedUrlBytes = [System.Convert]::FromBase64String($logZipSas)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)


## get guest agent installation path
$serviceName="WindowsAzureGuestAgent"
$serviceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$gaInstallPath = Get-ItemPropertyValue -Path $serviceKeyPath -Name "ImagePath"
$gaFolder = Split-Path -Path $gaInstallPath -Parent

## get CollectGuestLogs.exe path
$collectGuestLogExePath = $gaFolder + "\CollectGuestLogs.exe"
## run CollectGuestLogs.exe to collect log zip
## upload the zip to blob sas url

$currentFolder = $PWD.Path
$logZipPath = $currentFolder + "\VMAgentLogs.zip"; 

Write-Host "CollectGuestLogExe path: $collectGuestLogExePath"

Start-Process -FilePath $collectGuestLogExePath -WorkingDirectory $currentFolder -ArgumentList "-Mode:full -FileName:$logZipPath" -Wait -NoNewWindow

$headers = @{
    'x-ms-blob-type' = 'BlockBlob'
}

#Upload File...
Invoke-RestMethod -Uri $decodedUrlString -Method Put -Headers $headers -InFile $logZipPath