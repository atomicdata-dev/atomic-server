#!/bin/bash
CERT_FILE="cert.p12"
PASSWD=ieULXCnL
MT_EORI="EU.EORI.NL30000001"

export ASSERTION_TOKEN=$(python3 get_client_assertion.py -c "$CERT_FILE" -p $PASSWD -t $MT_EORI)

export ACCESS_TOKEN_JSON=$(curl --location 'https://idm.mt-dataexchange.nl/oauth2/token' \
--header 'Accept: application/json' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=client_credentials' \
--data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
--data-urlencode 'client_id=EU.EORI.NL30000003' \
--data-urlencode 'scope=iSHARE' \
--data-urlencode "client_assertion=$ASSERTION_TOKEN")

echo $ACCESS_TOKEN_JSON | jq
