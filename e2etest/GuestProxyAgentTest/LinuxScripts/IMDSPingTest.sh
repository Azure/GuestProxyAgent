#!/bin/bash

# make 10 requests if any failed, will failed the test for tcp port scalability config
for i in {1..10}; do
    url="http://169.254.169.254/metadata/instance?api-version=2020-06-01"
    statusCode=$(curl -s -o /dev/null -w "%{http_code}" $url)
    if [ $statusCode -eq 200 ]; then
        echo "Response status code is OK (200)"
    else
        echo "Ping test failed. Response status code is $statusCode"
        exit -1
    fi
    sleep 1
done

exit 0