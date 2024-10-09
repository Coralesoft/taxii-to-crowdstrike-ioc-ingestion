#!/bin/sh
# TAXII to CrowdStrike IOC Ingestion Script
# Script to poll a STIX/TAXII server for IOCs and ingest them into CrowdStrike Falcon.
# Developed by C.Brown (dev@coralesoft.nz)
# This software is released under the MIT License.
# See the LICENSE file in the project root for the full license text.
# Last revised 09/10/2024
# version 2024.10.2
#-----------------------------------------------------------------------
# Version      Date         Notes:
# 2024.10.1        Initial Public Release
# 2024.10.2    09.10.2024   Added error handling, logging, and retries for robustness
#-----------------------------------------------------------------------

# CrowdStrike Falcon API credentials (load from environment or configuration)
CLIENT_ID="${CLIENT_ID:-your_client_id}"
CLIENT_SECRET="${CLIENT_SECRET:-your_client_secret}"

# TAXII server credentials
TAXII_SERVER_URL="${TAXII_SERVER_URL:-https://taxii.server.url}"
TAXII_USERNAME="${TAXII_USERNAME:-your_taxii_username}"
TAXII_PASSWORD="${TAXII_PASSWORD:-your_taxii_password}"
TAXII_COLLECTION="${TAXII_COLLECTION:-your_taxii_collection}"

LOG_FILE="/var/log/taxii_to_crowdstrike.log"
MAX_RETRIES=3

log() {
    echo "$(date) - $1" | tee -a "$LOG_FILE"
}

# Retry function to handle transient failures (e.g., network errors)
retry() {
    local n=1
    local max=$MAX_RETRIES
    local delay=5
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
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

# Poll the TAXII server and retrieve STIX data
poll_taxii_server() {
    log "Polling TAXII server at $TAXII_SERVER_URL for collection $TAXII_COLLECTION..."

    TAXII_RESPONSE=$(curl -s -u "$TAXII_USERNAME:$TAXII_PASSWORD" \
      -H "Content-Type: application/xml" \
      -d "<taxii_poll_request_xml>" \
      "$TAXII_SERVER_URL/collections/$TAXII_COLLECTION/poll")

    if [ -z "$TAXII_RESPONSE" ]; then
        log "Failed to poll TAXII server. Exiting..."
        exit 1
    else
        log "TAXII data retrieved."
    fi
}

# Extract IOCs from the TAXII response
extract_iocs() {
    log "Extracting IOCs from TAXII response..."

    IOCs=$(echo "$TAXII_RESPONSE" | jq -r '.objects[] | select(.type=="indicator") | .pattern' | grep "domain-name" | cut -d"'" -f2)

    if [ -z "$IOCs" ]; then
        log "No IOCs found in TAXII response."
        exit 1
    else
        log "IOCs extracted: $IOCs"
    fi
}

# Calculate expiration date 3 months from today
calculate_expiration_date() {
    EXPIRATION_DATE=$(date -u -d "+3 months" +"%Y-%m-%dT%H:%M:%SZ")
    echo "$EXPIRATION_DATE"
}

# Check if an IOC already exists in CrowdStrike
check_ioc_exists() {
    local ioc_value=$1

    EXISTING_IOC=$(curl -s -X GET "https://api.crowdstrike.com/indicators/queries/iocs/v1?value=$ioc_value" \
      -H "Authorization: Bearer $ACCESS_TOKEN")

    if [ -z "$EXISTING_IOC" ]; then
        return 1  # IOC does not exist
    else
        return 0  # IOC exists
    fi
}

# Push or update IOCs in CrowdStrike Falcon
push_iocs_to_crowdstrike() {
    log "Pushing or updating IOCs in CrowdStrike Falcon..."

    for IOC in $IOCs; do
        log "Processing IOC: $IOC"

        EXPIRATION_DATE=$(calculate_expiration_date)

        check_ioc_exists "$IOC"
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

# Step 1: Get the CrowdStrike Falcon OAuth2 token
retry get_crowdstrike_token

# Step 2: Poll the TAXII server for IOCs
retry poll_taxii_server

# Step 3: Extract the IOCs from the TAXII response
retry extract_iocs

# Step 4: Push or update the IOCs in CrowdStrike Falcon
retry push_iocs_to_crowdstrike

log "IOC ingestion and management process complete."

