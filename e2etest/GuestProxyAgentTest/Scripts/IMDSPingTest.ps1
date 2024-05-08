# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

$i=0
# make 10 requests if any failed, will failed the test for tcp port scalability config
while($i -lt 10){
    try {
        $url = "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
        $webRequest = [System.Net.HttpWebRequest]::Create($url)	
        $webRequest.Headers.Add("Metadata", "True")
        $response = $webRequest.GetResponse()
        if ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK -and $response.Headers.Keys -contains "x-ms-azure-host-authorization") {
            Write-Output "Response status code is OK (200) and contains authorization header"
        }
        else {
            Write-Error "Ping test failed. Response status code is $($response.StatusCode)"
            exit -1
        }
        $webRequest.Abort()
    }
    catch {
        Write-Error "An error occurred: $_"
        exit -1
    }
    start-sleep -Seconds 1
    $i++
}
exit 0