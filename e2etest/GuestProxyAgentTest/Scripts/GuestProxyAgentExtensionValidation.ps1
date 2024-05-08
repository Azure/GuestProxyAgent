# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$customOutputJsonSAS    
)

$decodedUrlBytes = [System.Convert]::FromBase64String($customOutputJsonSAS)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

Write-Output "Start Guest Proxy Agent Extension Validation"

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
            Write-Output "Got proxy agent extension registry key path: " $nonRootRegKeyPath
            break
        } 
    } 
    if ($nonRootRegKeyPath -ne $null) {
        $reigstrykeyPath = $nonRootRegKeyPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM:'
        $PIRversion = ($reigstrykeyPath -split "_")[1]
        Write-Output "PIR Version: $PIRversion"
        if (((Get-Item -Path $reigstrykeyPath).GetValue("SequenceNumber") -ne $null) -and ((Get-Item -Path $reigstrykeyPath).GetValue("StatusFolder") -ne $null)) {
            $seqNo = (Get-ItemProperty -Path $reigstrykeyPath).SequenceNumber
            Write-Output "Seq No: $seqNo"
            $statusFolderPath = (Get-ItemProperty -Path $reigstrykeyPath).StatusFolder
            Write-Output "Status Folder: $statusFolderPath"
            $statusFilePath = [IO.Path]::Combine($statusFolderPath, $seqNo + ".status")
            Write-Output "Status file path: $statusFilePath"
            break
        } 
    }

    if ($stopwatch.Elapsed.TotalSeconds -ge $timeoutInSeconds) {
        Write-Output "Timeout reached. Error, The registry key does not have proxy agent extension."
        exit 1
    }
    start-sleep -Seconds 3
} until ($false)


$extensionFolder = Split-Path -Path $statusFolderPath -Parent
Write-Output "Extension Folder: $extensionFolder"
$PIRExePath = [IO.Path]::Combine($extensionFolder, "ProxyAgentExt.exe")

Write-Output "TEST: ProxyAgentVMExtension Status is succesful, Check that status file is success with 5 minute timeout"
$guestProxyAgentExtensionStatusObjGenerated = $false
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
do {
    $boolStatus = Test-Path -Path $statusFilePath
    if ($boolStatus) {
        $json = Get-Content $statusFilePath | Out-String | ConvertFrom-Json
        $extensionStatus = $json.status.status
        if ($extensionStatus -eq "success") {
            Write-Output "The extension status is success: $extensionStatus."
            $guestProxyAgentExtensionStatusObjGenerated = $true
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

Write-Output "TEST: ProxyAgentVMExtension Serivce is started and success"  
$serviceName = "GuestProxyAgentVMExtension"
$guestProxyAgentExtensionServiceExist = $false
$guestProxyAgentExtensionServiceStatus = $false 
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -ne $null) {
    $serviceStatus = $service.Status 
    Write-Output "The service $serviceName exists with status $serviceStatus." 
    $guestProxyAgentExtensionServiceExist = $true
    $guestProxyAgentExtensionServiceStatus = $true
} 

Write-Output "TEST: ProxyAgentVMExtension process is running "
$processName = "ProxyAgentExt"
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue
$guestProxyAgentExtensionProcessExist = $true
if ($process -ne $null) {
    Write-Output "The process $processName exists."
} else {
    $guestProxyAgentExtensionProcessExist = $false
    Write-Output "The process $processName does not exist."
}

Write-Output "TEST: ProxyAgent version running in VM is the same as expected version" 
$proxyAgentExeCmd = $extensionFolder + "\ProxyAgent\ProxyAgent\GuestProxyAgent.exe --version"
$proxyAgentVersion = Invoke-Expression $proxyAgentExeCmd
Write-Output "proxy agent version from extension folder: $proxyAgentVersion"
$guestProxyAgentExtensionVersion = $false
$proxyAgentStatus = $json.status.substatus[1].formattedMessage.message
$jsonObject = $proxyAgentStatus | ConvertFrom-json
$extractedVersion = $jsonObject.version
if ($extractedVersion -eq $proxyAgentVersion){ 
    Write-Output "The proxy agent version matches the expected version"
    $guestProxyAgentExtensionVersion = $true
} else {
    Write-Output "Error, the proxy agent version [ $extractedVersion ] does not match expected version [ $proxyAgentVersion ]"
}

Write-Output "TEST: Check detailed status of the extension if key latch is successful" 
$guestProxyAgentExtensionKeyLatch = $false
if ($proxyAgentStatus -like "*ready to use*") {
    Write-Output "The keylatch status is $proxyAgentStatus."
    $guestProxyAgentExtensionKeyLatch = $true
} else {
    Write-Output "Error the keylatch status is not ready: $proxyAgentStatus."
}

$jsonString = '{ "guestProxyAgentExtensionServiceExist": ' + $guestProxyAgentExtensionServiceExist.ToString().ToLower() `
+ ', "guestProxyAgentExtensionProcessExist": ' + $guestProxyAgentExtensionProcessExist.ToString().ToLower() `
+ ', "guestProxyAgentExtensionServiceStatus": ' + $guestProxyAgentExtensionServiceStatus.ToString().ToLower() `
+ ', "guestProxyAgentExtensionStatusObjGenerated": ' + $guestProxyAgentExtensionStatusObjGenerated.ToString().ToLower() `
+ ', "guestProxyAgentExtensionVersion": ' + $guestProxyAgentExtensionVersion.ToString().ToLower() `
+ ', "guestProxyAgentExtensionKeyLatch": ' + $guestProxyAgentExtensionKeyLatch.ToString().ToLower() ` + '}'

Write-Output $jsonString

Set-Content -Path $customOutputJsonPath -Value $jsonString

$headers = @{
    'x-ms-blob-type' = 'BlockBlob'
}

Write-Output "Upload File..."

Invoke-RestMethod -Uri $decodedUrlString -Method Put -Headers $headers -InFile $customOutputJsonPath