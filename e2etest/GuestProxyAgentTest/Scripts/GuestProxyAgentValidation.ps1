# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$customOutputJsonSAS,    
    [string]$expectedSecureChannelState
)

$decodedUrlBytes = [System.Convert]::FromBase64String($customOutputJsonSAS)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

Write-Output "$((Get-Date).ToUniversalTime()) - Start Guest Proxy Agent Validation"
Write-Output "$((Get-Date).ToUniversalTime()) - expectedSecureChannelState=$expectedSecureChannelState"

$currentFolder = $PWD.Path
$customOutputJsonPath = $currentFolder + "\proxyagentvalidation.json"; 
New-Item -ItemType File -Path $customOutputJsonPath

$serviceName = "GuestProxyAgent"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$guestProxyAgentServiceExist = $true
$guestProxyAgentServiceStatus = ""
$guestProxyAgentProcessExist = $true

if ($null -ne $service) {
    Write-Output "$((Get-Date).ToUniversalTime()) - The service $serviceName exists."    
    $guestProxyAgentServiceStatus = $service.Status
} else {
    Write-Output "$((Get-Date).ToUniversalTime()) - The service $serviceName does not exist."
    $guestProxyAgentServiceExist = $false
    $guestProxyAgentServiceStatus = "service not exists"
}

$processName = "GuestProxyAgent"

$process = Get-Process -Name $processName -ErrorAction SilentlyContinue

if ($null -ne $process) {
    Write-Output "$((Get-Date).ToUniversalTime()) - The process $processName exists."
} else {
    $guestProxyAgentProcessExist = $false
    Write-Output "$((Get-Date).ToUniversalTime()) - The process $processName does not exist."
}

$folderPath = "C:\WindowsAzure\ProxyAgent\Logs"
$guestProxyAgentLogGenerated = $false

if (Test-Path -Path $folderPath -PathType Container) {
    Write-Output "$((Get-Date).ToUniversalTime()) - The folder $folderPath exists."
    $files = Get-ChildItem -Path $folderPath -File
    if ($files.Count -gt 0) {
        Write-Output "$((Get-Date).ToUniversalTime()) - The folder $folderPath contains files."
        $guestProxyAgentLogGenerated = $true
    } else {
        Write-Output "$((Get-Date).ToUniversalTime()) - The folder $folderPath is empty."
    }
} else {
    Write-Output "$((Get-Date).ToUniversalTime()) - The folder $folderPath does not exist."
}

# check status.json file Content
## check timestamp of last entry in status.json file
## check the secure channel status
$timeoutInSeconds = 300  
$statusFilePath = [IO.Path]::Combine($folderPath,  "status.json")
Write-Output "$((Get-Date).ToUniversalTime()) - Checking GPA status file $statusFilePath with 5 minute timeout"
$secureChannelState = ""
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$currentUtcTime = (Get-Date).ToUniversalTime()
do {
    $boolStatus = Test-Path -Path $statusFilePath
    if ($boolStatus) {
        $json = Get-Content $statusFilePath | Out-String | ConvertFrom-Json
        $timestamp = $json.timestamp
        if ($null -ne $timestamp -and $timestamp -ne "") {
            Write-Output "$((Get-Date).ToUniversalTime()) - The status.json file contains a valid timestamp: $timestamp"
            # parse the timestamp to UTC DateTime object, if must later than $currentUtcTime 
            $timestampDateTime = [DateTime]::Parse($timestamp).ToUniversalTime()
            if ($timestampDateTime -gt $currentUtcTime) {
                Write-Output "$((Get-Date).ToUniversalTime()) - The status.json timestamp $timestampDateTime is later than $currentUtcTime."
                ## check secure channel status
                $secureChannelState = $json.proxyAgentStatus.keyLatchStatus.states.secureChannelState
                Write-Output "$((Get-Date).ToUniversalTime()) - The secure channel status is $secureChannelState."
                if ($secureChannelState -eq $expectedSecureChannelState) {
                    Write-Output "$((Get-Date).ToUniversalTime()) - The secure channel status '$secureChannelState' matches the expected state: '$expectedSecureChannelState'."
                   # break
                } else {
                    Write-Output "$((Get-Date).ToUniversalTime()) - The secure channel status '$secureChannelState' does not match the expected state: '$expectedSecureChannelState'."
                }

                if ($stopwatch.Elapsed.TotalSeconds -ge $timeoutInSeconds) {
                    Write-Output "$((Get-Date).ToUniversalTime()) - Timeout reached. Error, The secureChannelState is '$secureChannelState'."
                    break
                }
            }
        } else {
            Write-Output "$((Get-Date).ToUniversalTime()) - The status.json file does not contain a valid timestamp yet."
        }
    }
    start-sleep -Seconds 3
} until ($false)

$jsonString = '{"guestProxyAgentServiceInstalled": ' + $guestProxyAgentServiceExist.ToString().ToLower() `
        + ', "guestProxyProcessStarted": ' + $guestProxyAgentProcessExist.ToString().ToLower() `
        + ', "guestProxyAgentServiceStatus": "' + $guestProxyAgentServiceStatus `
        + ', "secureChannelState": "' + $secureChannelState `
        + '", "guestProxyAgentLogGenerated": ' + $guestProxyAgentLogGenerated.ToString().ToLower() + '}'

Write-Output "$((Get-Date).ToUniversalTime()) - $jsonString"

Set-Content -Path $customOutputJsonPath -Value $jsonString

$headers = @{
    'x-ms-blob-type' = 'BlockBlob'
}

#Upload File...
Invoke-RestMethod -Uri $decodedUrlString -Method Put -Headers $headers -InFile $customOutputJsonPath
