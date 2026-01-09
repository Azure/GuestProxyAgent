# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$customOutputJsonSAS,
    [string]$expectedProxyAgentVersion
)
Write-Output "$((Get-Date).ToUniversalTime()) - expectedProxyAgentVersion=$expectedProxyAgentVersion"
$decodedUrlBytes = [System.Convert]::FromBase64String($customOutputJsonSAS)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

Write-Output "$((Get-Date).ToUniversalTime()) - Start Guest Proxy Agent Extension Validation"

$currentFolder = $PWD.Path
$customOutputJsonPath = $currentFolder + "\proxyagentextensionvalidation.json"; 
New-Item -ItemType File -Path $customOutputJsonPath -Force

$timeoutInSeconds = 300  
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
do {
    $nonRootRegKeyPath = $null
    $proxy = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows Azure\HandlerState"
    foreach ($obj in $proxy) { 
        if($obj.Name -like "*Microsoft.CPlat.ProxyAgent.ProxyAgentWindows*") 
        { 
            $nonRootRegKeyPath = $obj.Name 
            Write-Output "$((Get-Date).ToUniversalTime()) - Got proxy agent extension registry key path: " $nonRootRegKeyPath
            break
        } 
    } 
    if ($nonRootRegKeyPath -ne $null) {
        $registrykeyPath = $nonRootRegKeyPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM:'
        $PIRversion = ($registrykeyPath -split "_")[1]
        Write-Output "$((Get-Date).ToUniversalTime()) - PIR Version: $PIRversion"
        if (((Get-Item -Path $registrykeyPath).GetValue("SequenceNumber") -ne $null) -and ((Get-Item -Path $registrykeyPath).GetValue("StatusFolder") -ne $null)) {
            $seqNo = (Get-ItemProperty -Path $registrykeyPath).SequenceNumber
            Write-Output "$((Get-Date).ToUniversalTime()) - Seq No: $seqNo"
            $statusFolderPath = (Get-ItemProperty -Path $registrykeyPath).StatusFolder
            Write-Output "$((Get-Date).ToUniversalTime()) - Status Folder: $statusFolderPath"
            $statusFilePath = [IO.Path]::Combine($statusFolderPath, $seqNo + ".status")
            Write-Output "$((Get-Date).ToUniversalTime()) - Status file path: $statusFilePath"
            break
        } 
    }

    if ($stopwatch.Elapsed.TotalSeconds -ge $timeoutInSeconds) {
        Write-Output "$((Get-Date).ToUniversalTime()) - Timeout reached. Error, The registry key does not have proxy agent extension."
        exit 1
    }
    start-sleep -Seconds 3
} until ($false)

$extensionFolder = Split-Path -Path $statusFolderPath -Parent
Write-Output "$((Get-Date).ToUniversalTime()) - Extension Folder: $extensionFolder"
$PIRExePath = [IO.Path]::Combine($extensionFolder, "ProxyAgentExt.exe")

Write-Output "$((Get-Date).ToUniversalTime()) - TEST: ProxyAgentVMExtension Status is succesful, Check that status file is success with 5 minute timeout"
$guestProxyAgentExtensionStatusObjGenerated = $false
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
do {
    $boolStatus = Test-Path -Path $statusFilePath
    if ($boolStatus) {
        $json = Get-Content $statusFilePath | Out-String | ConvertFrom-Json
        $extensionStatus = $json.status.status
        if ($extensionStatus -eq "Success") {
            Write-Output "$((Get-Date).ToUniversalTime()) - The extension status is success: $extensionStatus."
            $guestProxyAgentExtensionStatusObjGenerated = $true
            break
        }
        if ($extensionStatus -eq "Error") {
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

Write-Output "$((Get-Date).ToUniversalTime()) - TEST: ProxyAgentVMExtension Service is started and success"  
$serviceName = "GuestProxyAgentVMExtension"
$guestProxyAgentExtensionServiceExist = $false
$guestProxyAgentExtensionServiceStatus = $false 
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -ne $null) {
    $serviceStatus = $service.Status 
    Write-Output "$((Get-Date).ToUniversalTime()) - The service $serviceName exists with status $serviceStatus." 
    $guestProxyAgentExtensionServiceExist = $true
    $guestProxyAgentExtensionServiceStatus = $true
} 

Write-Output "$((Get-Date).ToUniversalTime()) - TEST: ProxyAgentVMExtension process is running "
$processName = "ProxyAgentExt"
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue
$guestProxyAgentExtensionProcessExist = $true
if ($process -ne $null) {
    Write-Output "$((Get-Date).ToUniversalTime()) - The process $processName exists."
} else {
    $guestProxyAgentExtensionProcessExist = $false
    Write-Output "$((Get-Date).ToUniversalTime()) - The process $processName does not exist."
}

Write-Output "$((Get-Date).ToUniversalTime()) - TEST: ProxyAgent version running in VM is the same as expected version" 
$proxyAgentExeCmd = $extensionFolder + "\ProxyAgent\ProxyAgent\GuestProxyAgent.exe --version"
$proxyAgentVersion = Invoke-Expression $proxyAgentExeCmd
Write-Output "$((Get-Date).ToUniversalTime()) - proxy agent version from extension folder: $proxyAgentVersion"
$guestProxyAgentExtensionVersion = $false
$json = Get-Content $statusFilePath | Out-String | ConvertFrom-Json
if ($json.status.substatus -is [System.Collections.IEnumerable] -and $json.status.substatus.Count -gt 0) {
    Write-Output "$((Get-Date).ToUniversalTime()) - The 'substatus' array exists and has length greater than 0."
    $guestProxyAgentExtensionVersion = $true
} 
if ($guestProxyAgentExtensionVersion) {
    $proxyAgentStatus = $json.status.substatus[1].formattedMessage.message
    $jsonObject = $proxyAgentStatus | ConvertFrom-json
    $extractedVersion = $jsonObject.version
    if ($extractedVersion -ne $proxyAgentVersion) {
        Write-Output "$((Get-Date).ToUniversalTime()) - Error, the proxy agent version [ $extractedVersions ] does not match the version [ $proxyAgentVersion ]"
        $guestProxyAgentExtensionVersion = $false
    }
    if ($expectedProxyAgentVersion -ne "0") {
        $cleanExpectedProxyAgentVersion = $expectedProxyAgentVersion.Trim()
        if ($extractedVersion -eq $cleanExpectedProxyAgentVersion){ 
            Write-Output "$((Get-Date).ToUniversalTime()) - After Update Version check: The proxy agent version matches the expected and extracted version"
        } else {
            Write-Output "$((Get-Date).ToUniversalTime()) - After Update Version check: Error, the proxy agent version [ $extractedVersion ] does not match expected version [ $cleanExpectedProxyAgentVersion ]"
            $guestProxyAgentExtensionVersion = $false
        }
    }
}

Write-Output "$((Get-Date).ToUniversalTime()) - TEST: Check detailed status of the extension if InstanceView is successful" 
$guestProxyAgentExtensionInstanceView = $false
if ($proxyAgentStatus -like "*SUCCESS*") {
    Write-Output "$((Get-Date).ToUniversalTime()) - The InstanceView status is $proxyAgentStatus."
    $guestProxyAgentExtensionInstanceView = $true
} else {
    Write-Output "$((Get-Date).ToUniversalTime()) - Error the InstanceView status is not ready: $proxyAgentStatus."
}

$jsonString = '{ "guestProxyAgentExtensionServiceExist": ' + $guestProxyAgentExtensionServiceExist.ToString().ToLower() `
+ ', "guestProxyAgentExtensionProcessExist": ' + $guestProxyAgentExtensionProcessExist.ToString().ToLower() `
+ ', "guestProxyAgentExtensionServiceStatus": ' + $guestProxyAgentExtensionServiceStatus.ToString().ToLower() `
+ ', "guestProxyAgentExtensionStatusObjGenerated": ' + $guestProxyAgentExtensionStatusObjGenerated.ToString().ToLower() `
+ ', "guestProxyAgentExtensionVersion": ' + $guestProxyAgentExtensionVersion.ToString().ToLower() `
+ ', "guestProxyAgentExtensionInstanceView": ' + $guestProxyAgentExtensionInstanceView.ToString().ToLower() ` + '}'

Write-Output "$((Get-Date).ToUniversalTime()) - $jsonString"

Set-Content -Path $customOutputJsonPath -Value $jsonString

$headers = @{
    'x-ms-blob-type' = 'BlockBlob'
}

Write-Output "$((Get-Date).ToUniversalTime()) - Upload File..."

Invoke-RestMethod -Uri $decodedUrlString -Method Put -Headers $headers -InFile $customOutputJsonPath