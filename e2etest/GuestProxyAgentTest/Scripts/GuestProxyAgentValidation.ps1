# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$customOutputJsonSAS    
)

$decodedUrlBytes = [System.Convert]::FromBase64String($customOutputJsonSAS)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

Write-Output "Start Guest Proxy Agent Validation"

$currentFolder = $PWD.Path
$customOutputJsonPath = $currentFolder + "\proxyagentvalidation.json"; 
New-Item -ItemType File -Path $customOutputJsonPath

$serviceName = "GuestProxyAgent"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$guestProxyAgentServiceExist = $true
$guestProxyAgentServiceStatus = ""
$guestProxyAgentProcessExist = $true

if ($service -ne $null) {
    Write-Output "The service $serviceName exists."    
    $guestProxyAgentServiceStatus = $service.Status
} else {
    Write-Output "The service $serviceName does not exist."
    $guestProxyAgentServiceExist = $false
    $guestProxyAgentServiceStatus = "service not exists"
}

$processName = "GuestProxyAgent"

$process = Get-Process -Name $processName -ErrorAction SilentlyContinue

if ($process -ne $null) {
    Write-Output "The process $processName exists."
} else {
    $guestProxyAgentProcessExist = $false
    Write-Output "The process $processName does not exist."
}

$folderPath = "C:\WindowsAzure\ProxyAgent\Logs"
$guestProxyAgentLogGenerated = $false

if (Test-Path -Path $folderPath -PathType Container) {
    Write-Output "The folder $folderPath exists."
    $files = Get-ChildItem -Path $folderPath -File
    if ($files.Count -gt 0) {
        Write-Output "The folder $folderPath contains files."
        $guestProxyAgentLogGenerated = $true
    } else {
        Write-Output "The folder $folderPath is empty."
    }
} else {
    Write-Output "The folder $folderPath does not exist."
}


$jsonString = '{"guestProxyAgentServiceInstalled": ' + $guestProxyAgentServiceExist.ToString().ToLower() `
        + ', "guestProxyProcessStarted": ' + $guestProxyAgentProcessExist.ToString().ToLower() `
        + ', "guestProxyAgentServiceStatus": "' + $guestProxyAgentServiceStatus `
        + '", "guestProxyAgentLogGenerated": ' + $guestProxyAgentLogGenerated.ToString().ToLower() + '}'

Write-Output $jsonString

Set-Content -Path $customOutputJsonPath -Value $jsonString

$headers = @{
    'x-ms-blob-type' = 'BlockBlob'
}

#Upload File...
Invoke-RestMethod -Uri $decodedUrlString -Method Put -Headers $headers -InFile $customOutputJsonPath
