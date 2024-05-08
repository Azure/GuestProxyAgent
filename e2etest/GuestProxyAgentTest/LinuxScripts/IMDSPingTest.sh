#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# make 10 requests if any failed, will failed the test for tcp port scalability config
for i in {1..10}; do
    url="http://169.254.169.254/metadata/instance?api-version=2020-06-01"
    statusCode=$(curl -s -o /dev/null -w "%{http_code}" -H "Metadata:True" $url)
    if [ $statusCode -eq 200 ]; then
        echo "Response status code is OK (200)"
    else
        echo "Ping test failed. Response status code is $statusCode"
        exit -1
    fi
    sleep 1
    authorizationHeader=$(curl -s -I -H "Metadata:True" $url | grep -Fi "x-ms-azure-host-authorization")
    if [ "$authorizationHeader" = "" ]; then
        echo "Response authorization header not exist"
        exit -1
    else
        echo "Response authorization header exists"
    fi
    sleep 1
done

exit 0