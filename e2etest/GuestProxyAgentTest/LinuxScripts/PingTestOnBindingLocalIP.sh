
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - imdsMode=$imdsMode"

expectedHttpCode=200
if [ "${imdsMode,,}" = "enforce" ]; then
    expectedHttpCode=401
fi
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - imdsMode=$imdsMode and expectedHttpCode=$expectedHttpCode"

url="http://169.254.169.254/metadata/instance?api-version=2020-06-01"
localIP=$(hostname -I | awk '{print $1}')
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