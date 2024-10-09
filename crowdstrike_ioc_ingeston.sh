#!/bin/sh
# TAXII to CrowdStrike IOC Ingestion Script
# Script to poll a STIX/TAXII server for IOCs and ingest them into CrowdStrike Falcon.
# Developed by C.Brown (dev@coralesoft.nz)
# This software is released under the MIT License.
# See the LICENSE file in the project root for the full license text.
# Last revised 09/10/2024
# version 2024.10.4
#-----------------------------------------------------------------------
# Version      Date         Notes:
# 2024.10.1    08-10.2024   Initial Public Release
# 2024.10.2    09.10.2024   Added error handling, logging, and retries for robustness
# 2024.10.3    09.10.2024   Handle pagination of large datasets
# 2024.10.4    09.10.2024   Added improved token handling, error checking, and page-by-page processing
#-----------------------------------------------------------------------

# CrowdStrike Falcon API credentials (load from environment or configuration)
CLIENT_ID="${CLIENT_ID:-your_client_id}"
CLIENT_SECRET="${CLIENT_SECRET:-your_client_secret}"

# TAXII server credentials
TAXII_SERVER_URL="${TAXII_SERVER_URL:-https://taxii.server.url}"
TAXII_USERNAME="${TAXII_USERNAME:-your_taxii_username}"
TAXII_PASSWORD="${TAXII_PASSWORD:-your_taxii_password}"
TAXII_COLLECTION="${TAXII_COLLECTION:-your_taxii_collection}"

# Log file where script activity will be stored
LOG_FILE="/var/log/taxii_to_crowdstrike.log"
MAX_RETRIES=3

log() {
    echo "$(date) - $1" | tee -a "$LOG_FILE"
}

# Retry function to handle transient failures (e.g., network errors)
retry() {
    n=1
    max=$MAX_RETRIES
    delay=5
    while true; do
        "$@" && break || {
            if [ "$n" -lt "$max" ]; then
                n=$(expr "$n" + 1)
                log "Command failed. Attempt $n/$max. Retrying in $delay seconds..."
                sleep $delay
            else
                log "The command has failed after $n attempts."
                return 1
            fi
        }
    done
}

# Get the CrowdStrike Falcon OAuth2 token
get_crowdstrike_token() {
    log "Fetching CrowdStrike OAuth2 token..."
    TOKEN_RESPONSE=$(curl -s -X POST "https://api.crowdstrike.com/oauth2/token" \
      -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
    
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
    if [ -z "$ACCESS_TOKEN" ]; then
        log "Failed to get OAuth2 token from CrowdStrike. Exiting..."
        exit 1
    else
        log "CrowdStrike OAuth2 token acquired."
    fi
}

# Poll the TAXII server for IOCs and handle pagination
poll_taxii_server() {
    log "Polling TAXII server at $TAXII_SERVER_URL for collection $TAXII_COLLECTION..."
    taxii_response=""
    more_data="true"
    next_token=""

    while [ "$more_data" = "true" ]; do
        if [ -n "$next_token" ]; then
            taxii_response=$(curl -s -u "$TAXII_USERNAME:$TAXII_PASSWORD" \
                -H "Content-Type: application/xml" \
                -d "<taxii_poll_request_xml next='$next_token'/>" \
                "$TAXII_SERVER_URL/collections/$TAXII_COLLECTION/poll")
        else
            taxii_response=$(curl -s -u "$TAXII_USERNAME:$TAXII_PASSWORD" \
                -H "Content-Type: application/xml" \
                -d "<taxii_poll_request_xml>" \
                "$TAXII_SERVER_URL/collections/$TAXII_COLLECTION/poll")
        fi

        # Process the IOCs from each page
        IOCs=$(echo "$taxii_response" | jq -r '.objects[] | select(.type=="indicator") | .pattern' | grep "domain-name" | cut -d"'" -f2)
        process_iocs "$IOCs"

        next_token=$(echo "$taxii_response" | jq -r '.next_token // empty')
        if [ -z "$next_token" ]; then
            more_data="false"
        fi
    done
}

# Check if IOC exists in CrowdStrike Falcon, handle pagination
check_ioc_exists_paginated() {
    ioc_value=$1
    more_data="true"
    next_token=""

    while [ "$more_data" = "true" ]; do
        if [ -n "$next_token" ]; then
            EXISTING_IOC=$(curl -s -X GET "https://api.crowdstrike.com/indicators/queries/iocs/v1?value=$ioc_value&next_token=$next_token" \
              -H "Authorization: Bearer $ACCESS_TOKEN")
        else
            EXISTING_IOC=$(curl -s -X GET "https://api.crowdstrike.com/indicators/queries/iocs/v1?value=$ioc_value" \
              -H "Authorization: Bearer $ACCESS_TOKEN")
        fi

        if [ -n "$EXISTING_IOC" ]; then
            return 0  # IOC exists
        fi

        next_token=$(echo "$EXISTING_IOC" | jq -r '.meta.pagination.next_token // empty')
        if [ -z "$next_token" ]; then
            more_data="false"
        fi
    done

    return 1  # IOC does not exist
}

# Push or update IOCs in CrowdStrike Falcon
push_iocs_to_crowdstrike() {
    log "Pushing or updating IOCs in CrowdStrike Falcon..."
    for IOC in $IOCs; do
        log "Processing IOC: $IOC"
        EXPIRATION_DATE=$(calculate_expiration_date)

        check_ioc_exists_paginated "$IOC"
        if [ $? -eq 0 ]; then
            log "IOC $IOC already exists. Updating..."
            JSON_PAYLOAD=$(jq -n --arg ioc "$IOC" --arg expiration "$EXPIRATION_DATE" '{
                type: "domain",
                value: $ioc,
                action: "detect",
                valid_until: $expiration,
                source: "TAXII Import"
            }')
            retry curl -s -X PATCH "https://api.crowdstrike.com/indicators/entities/iocs/v1" \
                -H "Authorization: Bearer $ACCESS_TOKEN" \
                -H "Content-Type: application/json" \
                -d "$JSON_PAYLOAD"
        else
            log "IOC $IOC is new. Adding..."
            JSON_PAYLOAD=$(jq -n --arg ioc "$IOC" --arg expiration "$EXPIRATION_DATE" '{
                type: "domain",
                value: $ioc,
                action: "detect",
                valid_until: $expiration,
                source: "TAXII Import"
            }')
            retry curl -s -X POST "https://api.crowdstrike.com/indicators/entities/iocs/v1" \
                -H "Authorization: Bearer $ACCESS_TOKEN" \
                -H "Content-Type: application/json" \
                -d "$JSON_PAYLOAD"
        fi
    done
}

# Main script execution
log "TAXII to CrowdStrike IOC ingestion started."
retry get_crowdstrike_token
retry poll_taxii_server
log "IOC ingestion and management process complete."
