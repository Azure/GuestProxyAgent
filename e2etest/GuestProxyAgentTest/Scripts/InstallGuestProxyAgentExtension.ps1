# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$devExtensionSas
)

$decodedUrlBytes = [System.Convert]::FromBase64String($devExtensionSas)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

Write-Output "$((Get-Date).ToUniversalTime()) - Starting install guest proxy agent extension script"

$proxy = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows Azure\HandlerState"
foreach ($obj in $proxy) { 
    if($obj.Name -like "*Microsoft.CPlat.ProxyAgent.ProxyAgentWindows*") 
    { 
        $nonRootRegKeyPath = $obj.Name
        Write-Output "$((Get-Date).ToUniversalTime()) - Got proxy agent extension registry key path: " $nonRootRegKeyPath
        $extensionRegKeyName = Split-Path -Path $nonRootRegKeyPath -Leaf
        # $extensionRegKeyName example: Microsoft.CPlat.ProxyAgent.ProxyAgentWindows_1.0.36
        Write-Output "$((Get-Date).ToUniversalTime()) - Proxy agent extension registry key name is: " $extensionRegKeyName
    } 
}  
$registrykeyPath = $nonRootRegKeyPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM:'
$PIRversion = ($registrykeyPath -split "_")[1]
Write-Output "$((Get-Date).ToUniversalTime()) - PIR Version: $PIRversion"
$seqNo = (Get-ItemProperty -Path $registrykeyPath).SequenceNumber
Write-Output "$((Get-Date).ToUniversalTime()) - Seq No: $seqNo"
$statusFolderPath = (Get-ItemProperty -Path $registrykeyPath).StatusFolder
Write-Output "$((Get-Date).ToUniversalTime()) - Status Folder: $statusFolderPath"
$statusFilePath = [IO.Path]::Combine($statusFolderPath, $seqNo + ".status")
Write-Output "$((Get-Date).ToUniversalTime()) - Status file path: $statusFilePath"
$extensionFolder = Split-Path -Path $statusFolderPath -Parent
Write-Output "$((Get-Date).ToUniversalTime()) - Extension Folder: $extensionFolder"
$PIRExePath = [IO.Path]::Combine($extensionFolder, "ProxyAgentExt.exe")
$PIRExtensionFolderZIPLocation = [IO.Path]::Combine($extensionFolder, $extensionRegKeyName + ".zip")

Write-Output "$((Get-Date).ToUniversalTime()) - Delete status file of PIR version" 
$boolStatus = Test-Path -Path $statusFilePath
if ($boolStatus) {
    Remove-Item -Path $statusFilePath -Force 
}

Write-Output "$((Get-Date).ToUniversalTime()) - Check that status file is success with 5 minute timeout" 
$timeoutInSeconds = 300  
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
do {
    $boolStatus = Test-Path -Path $statusFilePath
    if ($boolStatus) {
        $json = Get-Content $statusFilePath | Out-String | ConvertFrom-Json
        $extensionStatus = $json.status.status
        if ($extensionStatus -eq "success") {
            Write-Output "$((Get-Date).ToUniversalTime()) - The extension status is success: $extensionStatus."
            break
        }
        if ($extensionStatus -eq "error") {
            Write-Output "$((Get-Date).ToUniversalTime()) - The extension status is error: $extensionStatus."
            break
        }
        if ($stopwatch.Elapsed.TotalSeconds -ge $timeoutInSeconds) {
            Write-Output "$((Get-Date).ToUniversalTime()) - Timeout reached. Error, The extension status is $extensionStatus."
            break
        }
    }
    start-sleep -Seconds 3
} until ($false)

Write-Output "$((Get-Date).ToUniversalTime()) - Check that Extension service exists "
$serviceName = "GuestProxyAgentVMExtension"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -ne $null) {
    $serviceStatus = $service.Status
    Write-Output "$((Get-Date).ToUniversalTime()) - The service $serviceName exists with status: $serviceStatus."    
} else {
    Write-Output "$((Get-Date).ToUniversalTime()) - The service $serviceName does not exist."
}

Write-Output "$((Get-Date).ToUniversalTime()) - Check Extension process exists"
$processName = "ProxyAgentExt"
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue
if ($process -ne $null) {
    Write-Output "$((Get-Date).ToUniversalTime()) - The process $processName is running."
} else {
    Write-Output "$((Get-Date).ToUniversalTime()) - The process $processName is not running."
}

Write-Output "$((Get-Date).ToUniversalTime()) - Delete extension zip file $PIRExtensionFolderZIPLocation" 
Remove-Item -Path $PIRExtensionFolderZIPLocation -Force
wget $decodedUrlString -OutFile $PIRExtensionFolderZIPLocation
Write-Output "$((Get-Date).ToUniversalTime()) - downloaded the proxyagent extension file to path: " $PIRExtensionFolderZIPLocation

Write-Output "$((Get-Date).ToUniversalTime()) - net stop $serviceName"
net stop $serviceName

Write-Output "$((Get-Date).ToUniversalTime()) - TASKKILL /F /IM ProxyAgentExt.exe"
TASKKILL /F /IM ProxyAgentExt.exe

Write-Output "$((Get-Date).ToUniversalTime()) - Delete registry key at $registrykeyPath"
Remove-Item -Path $registrykeyPath -Recurse

Write-Output "$((Get-Date).ToUniversalTime()) - Delete status file $statusFilePath" 
Remove-Item -Path $statusFilePath -Force 
