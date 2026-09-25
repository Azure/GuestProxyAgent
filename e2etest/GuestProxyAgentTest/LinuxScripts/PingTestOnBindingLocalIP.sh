
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT


url="http://169.254.169.254/metadata/instance?api-version=2020-06-01"
localIP=$(hostname -I | awk '{print $1}')
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Starting ping test on local IP $localIP"

# make 10 requests if any failed, will failed the test
for i in {1..10}; do
    
    statusCode=$(curl --noproxy "*" -s -o /dev/null -w "%{http_code}" -H "Metadata:True" --interface "$localIP" "$url")
    if [ $statusCode -eq 200 ]; then
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Response status code is OK (200)"
    else
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - Ping test failed. Response status code is $statusCode"
        exit -1
    fi

    sleep 1
done

exit 0