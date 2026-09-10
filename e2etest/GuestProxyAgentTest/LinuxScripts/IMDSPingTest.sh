#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - imdsSecureChannelEnabled=$imdsSecureChannelEnabled"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - ipv6DualStackSupported=$ipv6DualStackSupported"

# make 10 requests if any failed, will failed the test
for i in {1..10}; do
    url="http://169.254.169.254/metadata/instance?api-version=2020-06-01"
    statusCode=$(curl --noproxy "*" -s -o /dev/null -w "%{http_code}" -H "Metadata:True" "$url")
    if [ $statusCode -eq 200 ]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response status code is OK (200)"
    else
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Ping test failed. Response status code is $statusCode"
        exit -1
    fi
    sleep 1

    authorizationHeader=$(curl --noproxy "*" -s -I -H "Metadata:True" "$url" | grep -Fi "x-ms-azure-host-authorization")
    if [ "${imdsSecureChannelEnabled,,}" = "true" ]  # case insensitive comparison
    then
        if [ "$authorizationHeader" = "" ]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response authorization header not exist"
            exit -1
        else
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response authorization header exists as expected"
        fi
        sleep 1
    else
        if [ "$authorizationHeader" = "" ]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response authorization header not exist as expected"
        else
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response authorization header exists"
            exit -1
        fi
        sleep 1
	fi
done

if [ "${ipv6DualStackSupported,,}" != "true" ]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 dual stack is not supported on this GPA. Skipping the IPv4-mapped IPv6 ping test."
    exit 0
fi

if [ ! -e /proc/net/if_inet6 ] ||
    { [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 1 ]; }; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 is not supported or is disabled on this VM. Skipping the IPv4-mapped IPv6 ping test."
    exit 0
fi

if ! curl --version | grep -qE '^Features:.*[[:space:]]IPv6([[:space:]]|$)'; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - curl does not support IPv6. Skipping the IPv4-mapped IPv6 ping test."
    exit 0
fi

# make 10 requests if any failed, will failed the test
for i in {1..10}; do
    ipv6_dual_stack_url="http://[::ffff:169.254.169.254]/metadata/instance?api-version=2020-06-01"
    statusCode=$(curl --noproxy "*" --ipv6 --silent --show-error --output /dev/null --write-out "%{http_code}" -H "Metadata:True" -H "Host: 169.254.169.254" "$ipv6_dual_stack_url")
    curlExitCode=$?
    if [ $curlExitCode -ne 0 ]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Ping test failed. curl exit code is $curlExitCode"
        exit -1
    elif [ "$statusCode" -eq 200 ]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Response status code is OK (200)"
    else
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Ping test failed. Response status code is $statusCode"
        exit -1
    fi
    sleep 1

    responseHeaders=$(curl --noproxy "*" --ipv6 --silent --show-error --head -H "Metadata:True" -H "Host: 169.254.169.254" "$ipv6_dual_stack_url")
    curlExitCode=$?
    if [ $curlExitCode -ne 0 ]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Ping test failed while reading response headers. curl exit code is $curlExitCode"
        exit -1
    fi
    authorizationHeader=$(printf '%s\n' "$responseHeaders" | grep -Fi "x-ms-azure-host-authorization")
    if [ "${imdsSecureChannelEnabled,,}" = "true" ]  # case insensitive comparison
    then
        if [ "$authorizationHeader" = "" ]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Response authorization header not exist"
            exit -1
        else
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Response authorization header exists as expected"
        fi
        sleep 1
    else
        if [ "$authorizationHeader" = "" ]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Response authorization header not exist as expected"
        else
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IPv6 Dual Stack Response authorization header exists"
            exit -1
        fi
        sleep 1
	fi
done
exit 0