# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$customOutputJsonSAS,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$loadedModulesBaseLineSAS
)

Write-Output "Start Guest Proxy Agent Loadded Module Validation"

$decodedUrlBytes = [System.Convert]::FromBase64String($customOutputJsonSAS)
$decodedUrlString = [System.Text.Encoding]::UTF8.GetString($decodedUrlBytes)

$moduleBaselineUrlBytes = [System.Convert]::FromBase64String($loadedModulesBaseLineSAS)
$moduleBaselineUrlString = [System.Text.Encoding]::UTF8.GetString($moduleBaselineUrlBytes)

$currentFolder = $PWD.Path
$customOutputJsonPath = $currentFolder + "\validateLoadedModule.json"; 
$moduleBaselineFilePath = $currentFolder + "\moduleListBaseline.txt"; 

New-Item -ItemType File -Path $customOutputJsonPath
New-Item -ItemType File -Path $moduleBaselineFilePath


Invoke-WebRequest -Uri $moduleBaselineUrlString -OutFile $moduleBaselineFilePath

Write-Output "Downloaded baseline file"

$baseArray = @()

foreach ($line in Get-Content $moduleBaselineFilePath| Where-Object { $_.Trim() -ne '' }) {    
    $baseArray += $line.Trim().ToLower()
}

Write-Output "Read baseline list: $baseArray"

$processName = "GuestProxyAgent"
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue

$currentModulesArray = @()

if ($process -eq $null) {
    Write-Output "Process '$processName' not found."
} else {
    Write-Output "Loaded modules for process '$processName':"
    $modules = $process.Modules
    foreach ($module in $modules) {
        $moduleName = $module.ModuleName
		$currentModulesArray += $moduleName.Trim().ToLower()
        Write-Output "Module Name: $moduleName"        
    }
}

Write-Output "Current loaded list: $currentModulesArray"

$comparisonResult = Compare-Object -ReferenceObject $baseArray -DifferenceObject $currentModulesArray

$missedInBaselineModules = @()
$newAddedModules = @()
$isMatch = $false
if ($comparisonResult -eq $null -or $comparisonResult.Count -eq 0) {
    Write-Output "No differences found."
    $isMatch = $true
} else {
    Write-Output "Differences found:"
    # Display the differences
    foreach ($result in $comparisonResult) {
        $inputObject = '"' + $result.InputObject + '"'
        $sideIndicator = $result.SideIndicator

        if ($sideIndicator -eq "<=") {
            $missedInBaselineModules += $inputObject
        } else {
            $newAddedModules += $inputObject
        }
    }
}

$jsonString = '{ "isMatch": ' + $isMatch.ToString().ToLower() + ', "newAddedModules": [' + ($newAddedModules -join ",") + '], "missedInBaselineModules": [' + ($missedInBaselineModules -join ",") + ']}'

Set-Content -Path $customOutputJsonPath -Value $jsonString

$headers = @{
    'x-ms-blob-type' = 'BlockBlob'
}

Invoke-RestMethod -Uri $decodedUrlString -Method Put -Headers $headers -InFile $customOutputJsonPath
Write-Output "Uploaded json output result."
