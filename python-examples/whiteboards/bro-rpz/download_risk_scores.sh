#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [Recorded Future Token]"
    exit 1
fi
curl --header "Authorization: RF-TOKEN token=$1" "https://api.recordedfuture.com/query/list/HighRisk/IpAddress?output_version=2.0&format=csv/splunk" > highrisk.csv
