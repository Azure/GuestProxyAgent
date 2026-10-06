# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
param (
    [string]$imdsMode
)

$expectedHttpCode = [System.Net.HttpStatusCode]::OK
if ($imdsMode -eq "enforce") {
    $expectedHttpCode = [System.Net.HttpStatusCode]::Unauthorized
}

Write-Output "$((Get-Date).ToUniversalTime()) - imdsMode=$imdsMode and expectedHttpCode=$expectedHttpCode"

$localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet)[0].IPAddress.ToString()
Write-Output "$((Get-Date).ToUniversalTime()) - Starting ping test binding to local IP $localIP"
    
# make 10 requests if any failed, will failed the test
for ($i = 0; $i -lt 10; $i++) {
    try {
        $url = "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
        $webRequest = [System.Net.HttpWebRequest]::Create($url)
        $webRequest.Headers.Add("Metadata", "True")
        $webRequest.ServicePoint.BindIPEndPointDelegate = {
            return New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($localIP), 0)
        }
        $response = $webRequest.GetResponse()
        $webRequest.Abort()

        $statusCode = $response.StatusCode
        if ($statusCode -eq $expectedHttpCode) {
            Write-Output "$((Get-Date).ToUniversalTime()) - Response status code is expected ($expectedHttpCode)"
        }
        else {
            Write-Error "$((Get-Date).ToUniversalTime()) - Ping test failed. Response status code is expected ($expectedHttpCode), received ($statusCode)"
            exit -1
        }
    }
    catch {
        Write-Error "$((Get-Date).ToUniversalTime()) - An error occurred: $_"
        exit -1
    }
}
exit 0