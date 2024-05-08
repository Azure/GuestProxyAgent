# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

try {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet)[0].IPAddress.ToString()
    $url = "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
    $webRequest = [System.Net.HttpWebRequest]::Create($url)
    $webRequest.Headers.Add("Metadata", "True")
    $webRequest.ServicePoint.BindIPEndPointDelegate = {
        return New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($localIP), 0)
    }
    $response = $webRequest.GetResponse()

    if ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK -and $response.Headers.Keys -contains "x-ms-azure-host-authorization") {
        Write-Output "Response status code is OK (200) and contains authorization header"
    }
    else {
        Write-Error "Ping test failed. Response status code is $($response.StatusCode)"
        exit -1
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit -1
}
exit 0