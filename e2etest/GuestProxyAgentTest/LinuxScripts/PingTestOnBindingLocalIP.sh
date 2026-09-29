
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - imdsMode=$imdsMode"

expectedHttpCode=200
if [ "${imdsMode,,}" = "enforce" ]; then
    expectedHttpCode=401
fi
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - imdsMode=$imdsMode and expectedHttpCode=$expectedHttpCode"

url="http://169.254.169.254/metadata/instance?api-version=2020-06-01"
localIP=$(ip -4 route get 169.254.169.254 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}')
if [ -z "$localIP" ]; then
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Failed to determine the local IPv4 address used to reach IMDS"
    exit 1
fi
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Starting ping test binding to local IP $localIP"

# make 10 requests if any failed, will failed the test
for i in {1..10}; do
    
    statusCode=$(curl --noproxy "*" -s -o /dev/null -w "%{http_code}" -H "Metadata:True" --interface "$localIP" "$url")
    if [ "$statusCode" -eq "$expectedHttpCode" ]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response status code is expected ($expectedHttpCode)"
    else
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Ping test failed. Expected response status code $expectedHttpCode, received $statusCode"
        exit -1
    fi

    sleep 1
done

exit 0