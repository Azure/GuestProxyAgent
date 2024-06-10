# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$devExtensionSas
)

$decodedUrlBytes = [System.Convert]::FromBase64String($devExtensionSas)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

Write-Output "Starting install guest proxy agent extension script"

$proxy = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows Azure\HandlerState"
foreach ($obj in $proxy) { 
    if($obj.Name -like "*Microsoft.CPlat.ProxyAgent.ProxyAgentWindows*") 
    { 
        $nonRootRegKeyPath = $obj.Name 
        Write-Output "Got proxy agent extension registry key path: " $nonRootRegKeyPath
    } 
}  
$reigstrykeyPath = $nonRootRegKeyPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM:'
$PIRversion = ($reigstrykeyPath -split "_")[1]
Write-Output "PIR Version: $PIRversion"
$seqNo = (Get-ItemProperty -Path $reigstrykeyPath).SequenceNumber
Write-Output "Seq No: $seqNo"
$statusFolderPath = (Get-ItemProperty -Path $reigstrykeyPath).StatusFolder
Write-Output "Status Folder: $statusFolderPath"
$statusFilePath = [IO.Path]::Combine($statusFolderPath, $seqNo + ".status")
Write-Output "Status file path: $statusFilePath"
$extensionFolder = Split-Path -Path $statusFolderPath -Parent
Write-Output "Extension Folder: $extensionFolder"
$PIRExePath = [IO.Path]::Combine($extensionFolder, "ProxyAgentExt.exe")
$PIRExtensionFolderZIPLocation = [IO.Path]::Combine($extensionFolder, "Microsoft.CPlat.ProxyAgent.ProxyAgentWindows_" + $PIRversion + ".zip")

Write-Output "Delete status file of PIR version" 
$boolStatus = Test-Path -Path $statusFilePath
if ($boolStatus) {
    Remove-Item -Path $statusFilePath -Force 
}

Write-Output "Check that status file is success with 5 minute timeout" 
$timeoutInSeconds = 300  
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
do {
    $boolStatus = Test-Path -Path $statusFilePath
    if ($boolStatus) {
        $json = Get-Content $statusFilePath | Out-String | ConvertFrom-Json
        $extensionStatus = $json.status.status
        if ($extensionStatus -eq "success") {
            Write-Output "The extension status is success: $extensionStatus."
            break
        }
        if ($extensionStatus -eq "error") {
            Write-Output "The extension status is error: $extensionStatus."
            break
        }
        if ($stopwatch.Elapsed.TotalSeconds -ge $timeoutInSeconds) {
            Write-Output "Timeout reached. Error, The extension status is $extensionStatus."
            break
        }
    }
    start-sleep -Seconds 3
} until ($false)

Write-Output "Check that Extension service exists "
$serviceName = "GuestProxyAgentVMExtension"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -ne $null) {
    $serviceStatus = $service.Status
    Write-Output "The service $serviceName exists with status: $serviceStatus."    
} else {
    Write-Output "The service $serviceName does not exist."
}

Write-Output "Check Extension process exists"
$processName = "ProxyAgentExt"
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue
if ($process -ne $null) {
    Write-Output "The process $processName is running."
} else {
    Write-Output "The process $processName is not running."
}

Write-Output "Delete extension zip file $PIRExtensionFolderZIPLocation" 
Remove-Item -Path $PIRExtensionFolderZIPLocation -Force
wget $decodedUrlString -OutFile $PIRExtensionFolderZIPLocation
Write-Output "downloaded the proxyagent extension file to path: " $PIRExtensionFolderZIPLocation

TASKKILL /F /IM ProxyAgentExt.exe
Write-Output "TASKKILL /F /IM ProxyAgentExt.exe"

Write-Output "Delete registry key at $reigstrykeyPath"
Remove-Item -Path $reigstrykeyPath -Recurse

Write-Output "Delete status file $statusFilePath" 
Remove-Item -Path $statusFilePath -Force 
