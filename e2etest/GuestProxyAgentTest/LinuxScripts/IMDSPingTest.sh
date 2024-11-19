#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - imdsSecureChannelEnabled=$imdsSecureChannelEnabled"

# make 10 requests if any failed, will failed the test for tcp port scalability config
for i in {1..10}; do
    url="http://169.254.169.254/metadata/instance?api-version=2020-06-01"
    statusCode=$(curl -s -o /dev/null -w "%{http_code}" -H "Metadata:True" $url)
    if [ $statusCode -eq 200 ]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response status code is OK (200)"
    else
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Ping test failed. Response status code is $statusCode"
        exit -1
    fi
    sleep 1

    if [ "${imdsSecureChannelEnabled,,}" = "true" ]  # case insensitive comparison
    then
        authorizationHeader=$(curl -s -I -H "Metadata:True" $url | grep -Fi "x-ms-azure-host-authorization")
        if [ "$authorizationHeader" = "" ]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response authorization header not exist"
            exit -1
        else
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response authorization header exists"
        fi
        sleep 1
    else
		echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - IMDS secure channel is not enabled. Skipping x-ms-azure-host-authorization header validation"
	fi
done

exit 0