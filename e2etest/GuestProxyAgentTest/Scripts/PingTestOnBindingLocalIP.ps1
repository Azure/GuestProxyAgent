# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$imdsSecureChannelEnabled
)
Write-Output "imdsSecureChannelEnabled=$imdsSecureChannelEnabled"

try {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet)[0].IPAddress.ToString()
    $url = "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
    $webRequest = [System.Net.HttpWebRequest]::Create($url)
    $webRequest.Headers.Add("Metadata", "True")
    $webRequest.ServicePoint.BindIPEndPointDelegate = {
        return New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($localIP), 0)
    }
    $response = $webRequest.GetResponse()

    if ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
        Write-Output "Response status code is OK (200)"
    }
    else {
        Write-Error "Ping test failed. Response status code is $($response.StatusCode)"
        exit -1
    }

    if ($imdsSecureChannelEnabled -eq "true") {
        $responseHeaders = $response.Headers
		if ($responseHeaders["x-ms-azure-host-authorization"] -eq $null) {
			Write-Error "Ping test failed. Response does not contain x-ms-azure-host-authorization header"
			exit -1
		}
        else {
            Write-Output "Ping test passed. Response contains x-ms-azure-host-authorization header"
        }
    }
    else {
        Write-Output "IMDS secure channel is not enabled. Skipping x-ms-azure-host-authorization header validation"
		
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit -1
}
exit 0