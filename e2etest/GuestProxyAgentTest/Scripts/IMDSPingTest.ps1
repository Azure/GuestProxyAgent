# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$imdsSecureChannelEnabled, 
    [string]$ipv6DualStackSupported
)
Write-Output "$((Get-Date).ToUniversalTime()) - imdsSecureChannelEnabled=$imdsSecureChannelEnabled"
Write-Output "$((Get-Date).ToUniversalTime()) - ipv6DualStackSupported=$ipv6DualStackSupported"

function Test-IsIpv6UnsupportedError {
    param (
        [System.Exception]$Exception
    )

    while ($null -ne $Exception) {
        if ($Exception -is [System.PlatformNotSupportedException] -or
            $Exception -is [System.NotSupportedException]) {
            return $true
        }

        if ($Exception -is [System.Net.Sockets.SocketException]) {
            return $Exception.SocketErrorCode -in @(
                [System.Net.Sockets.SocketError]::AddressFamilyNotSupported,
                [System.Net.Sockets.SocketError]::AddressNotAvailable,
                [System.Net.Sockets.SocketError]::NetworkUnreachable,
                [System.Net.Sockets.SocketError]::OperationNotSupported,
                [System.Net.Sockets.SocketError]::ProtocolNotSupported
            )
        }

        $Exception = $Exception.InnerException
    }

    return $false
}

$i = 0
# make 10 requests if any failed, will failed the test
while ($i -lt 10) {
    try {
        $url = "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
        $webRequest = [System.Net.HttpWebRequest]::Create($url)	
        $webRequest.Headers.Add("Metadata", "True")
        $response = $webRequest.GetResponse()
        if ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
            Write-Output "$((Get-Date).ToUniversalTime()) - Response status code is OK (200)"
        }
        else {
            Write-Error "$((Get-Date).ToUniversalTime()) - Ping test failed. Response status code is $($response.StatusCode)"
            exit -1
        }

        $responseHeaders = $response.Headers
        if ("$imdsSecureChannelEnabled" -ieq "true") { # case insensitive comparison
            if ($null -eq $responseHeaders["x-ms-azure-host-authorization"]) {
                Write-Error "$((Get-Date).ToUniversalTime()) - Ping test failed. Response does not contain x-ms-azure-host-authorization header"
                exit -1
            }
            else {
                Write-Output "$((Get-Date).ToUniversalTime()) - Ping test passed. Response contains x-ms-azure-host-authorization header"
            }
        }
        else {
            if ($null -eq $responseHeaders["x-ms-azure-host-authorization"]) {
                Write-Output "$((Get-Date).ToUniversalTime()) - Ping test passed. Response does not contain x-ms-azure-host-authorization header as expected"
            }
            else {
                Write-Error "$((Get-Date).ToUniversalTime()) - Ping test failed. Response contains x-ms-azure-host-authorization header"
                exit -1
            }
        }

        $webRequest.Abort()
    }
    catch {
        Write-Error "$((Get-Date).ToUniversalTime()) - An error occurred: $_"
        exit -1
    }
    start-sleep -Seconds 1
    $i++
}

if (-not [System.Net.Sockets.Socket]::OSSupportsIPv6) {
    Write-Warning "$((Get-Date).ToUniversalTime()) - IPv6 is not supported on this VM. Skipping the IPv4-mapped IPv6 ping test."
    exit 0
}

$i = 0
while ($i -lt 10) {
    $tcpClient = $null
    $reader = $null
    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $tcpClient.Client.DualMode = $true
        $tcpClient.Connect([System.Net.IPAddress]::Parse("::ffff:169.254.169.254"), 80)

        $stream = $tcpClient.GetStream()
        $stream.ReadTimeout = 30000
        $stream.WriteTimeout = 30000
        $request = "GET /metadata/instance?api-version=2020-06-01 HTTP/1.1`r`nHost: 169.254.169.254`r`nMetadata: True`r`nConnection: close`r`n`r`n"
        $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($request)
        $stream.Write($requestBytes, 0, $requestBytes.Length)

        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII)
        $statusLine = $reader.ReadLine()
        if ($statusLine -match '^HTTP/\d(?:\.\d)? 200(?:\s|$)') {
            Write-Output "$((Get-Date).ToUniversalTime()) - IPv4-mapped IPv6 ping test response status code is OK (200)"
        }
        else {
            Write-Error "$((Get-Date).ToUniversalTime()) - IPv4-mapped IPv6 ping test failed. Response status is '$statusLine'"
            exit -1
        }

        $responseHeaders = @{}
        while (($headerLine = $reader.ReadLine()) -ne $null -and $headerLine.Length -gt 0) {
            $separator = $headerLine.IndexOf(':')
            if ($separator -gt 0) {
                $responseHeaders[$headerLine.Substring(0, $separator).Trim()] = $headerLine.Substring($separator + 1).Trim()
            }
        }

        if ("$imdsSecureChannelEnabled" -ieq "true") { # case insensitive comparison
            if ($null -eq $responseHeaders["x-ms-azure-host-authorization"]) {
                Write-Error "$((Get-Date).ToUniversalTime()) - IPv4-mapped IPv6 ping test failed. Response does not contain x-ms-azure-host-authorization header"
                exit -1
            }
            else {
                Write-Output "$((Get-Date).ToUniversalTime()) - IPv4-mapped IPv6 ping test passed. Response contains x-ms-azure-host-authorization header"
            }
        }
        else {
            if ($null -eq $responseHeaders["x-ms-azure-host-authorization"]) {
                Write-Output "$((Get-Date).ToUniversalTime()) - IPv4-mapped IPv6 ping test passed. Response does not contain x-ms-azure-host-authorization header as expected"
            }
            else {
                Write-Error "$((Get-Date).ToUniversalTime()) - IPv4-mapped IPv6 ping test failed. Response contains x-ms-azure-host-authorization header"
                exit -1
            }
        }
    }
    catch {
        if (Test-IsIpv6UnsupportedError -Exception $_.Exception) {
            Write-Warning "$((Get-Date).ToUniversalTime()) - IPv6 or dual-stack sockets are not supported on this VM. Skipping the IPv4-mapped IPv6 ping test. Error: $_"
            break
        }
        Write-Error "$((Get-Date).ToUniversalTime()) - IPv4-mapped IPv6 request failed: $_"
        exit -1
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
        if ($null -ne $tcpClient) {
            $tcpClient.Dispose()
        }
    }
    start-sleep -Seconds 1
    $i++
}
exit 0