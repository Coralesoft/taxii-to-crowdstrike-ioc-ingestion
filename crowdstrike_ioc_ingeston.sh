#!/bin/sh
# TAXII to CrowdStrike IOC Ingestion Script
# Script to poll a STIX/TAXII server for IOCs and ingest them into CrowdStrike Falcon.
# Developed by C.Brown (dev@coralesoft.nz)
# This software is released under the MIT License.
# See the LICENSE file in the project root for the full license text.
# Last revised 08/10/2024
# version 2024.10.1
#-----------------------------------------------------------------------
# Version      Date         Notes:
# 2024.10.1    08.10.2024   Initial Public Release
#-----------------------------------------------------------------------

# CrowdStrike Falcon API credentials
CLIENT_ID="your_client_id"
CLIENT_SECRET="your_client_secret"

# TAXII server credentials
TAXII_SERVER_URL="https://taxii.server.url"
TAXII_USERNAME="your_taxii_username"
TAXII_PASSWORD="your_taxii_password"
TAXII_COLLECTION="your_taxii_collection"

# Function to get CrowdStrike Falcon OAuth2 token
get_crowdstrike_token() {
  echo "Fetching CrowdStrike OAuth2 token..."
  
  # Make a POST request to the CrowdStrike OAuth2 API endpoint to get an access token
  TOKEN_RESPONSE=$(curl -s -X POST "https://api.crowdstrike.com/oauth2/token" \
    -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")

  # Extract the token from the response
  ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

  # Check if we successfully got the token
  if [ -z "$ACCESS_TOKEN" ]; then
    echo "Failed to get OAuth2 token from CrowdStrike. Exiting..."
    exit 1
  else
    echo "CrowdStrike OAuth2 token acquired."
  fi
}

# Function to poll the TAXII server and retrieve STIX data
poll_taxii_server() {
  echo "Polling TAXII server at $TAXII_SERVER_URL for collection $TAXII_COLLECTION..."

  # Make a POST request to the TAXII server (this example assumes a basic setup, adjust as needed)
  TAXII_RESPONSE=$(curl -s -u "$TAXII_USERNAME:$TAXII_PASSWORD" \
    -H "Content-Type: application/xml" \
    -d "<taxii_poll_request_xml>" \
    "$TAXII_SERVER_URL/collections/$TAXII_COLLECTION/poll")

  # Check if we got a valid response
  if [ -z "$TAXII_RESPONSE" ]; then
    echo "Failed to poll TAXII server. Exiting..."
    exit 1
  else
    echo "TAXII data retrieved."
  fi
}

# Function to extract IOCs from the TAXII response (example for domain names)
extract_iocs() {
  echo "Extracting IOCs from TAXII response..."

  # Assume STIX data is in JSON format (if XML, convert it or adjust parsing accordingly)
  IOCs=$(echo "$TAXII_RESPONSE" | jq -r '.objects[] | select(.type=="indicator") | .pattern' | grep "domain-name" | cut -d"'" -f2)

  if [ -z "$IOCs" ]; then
    echo "No IOCs found in TAXII response."
    exit 1
  else
    echo "IOCs extracted: $IOCs"
  fi
}

# Function to push IOCs to CrowdStrike Falcon
push_iocs_to_crowdstrike() {
  echo "Pushing IOCs to CrowdStrike Falcon..."

  for IOC in $IOCs; do
    echo "Processing IOC: $IOC"

    # Construct the JSON payload for each IOC
    JSON_PAYLOAD=$(jq -n --arg ioc "$IOC" '{
      type: "domain",
      value: $ioc,
      action: "detect",
      source: "TAXII Import"
    }')

    # Push the IOC to CrowdStrike Falcon using their API
    RESPONSE=$(curl -s -X POST "https://api.crowdstrike.com/indicators/entities/iocs/v1" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$JSON_PAYLOAD")

    # Check the response status
    STATUS_CODE=$(echo "$RESPONSE" | jq -r '.meta.code')

    if [ "$STATUS_CODE" -eq 201 ]; then
      echo "IOC successfully pushed: $IOC"
    else
      echo "Error pushing IOC: $IOC, Response: $RESPONSE"
    fi
  done
}

# Main script execution

# Step 1: Get the CrowdStrike Falcon OAuth2 token
get_crowdstrike_token

# Step 2: Poll the TAXII server for IOCs
poll_taxii_server

# Step 3: Extract the IOCs from the TAXII response
extract_iocs

# Step 4: Push the IOCs to CrowdStrike Falcon
push_iocs_to_crowdstrike

echo "IOC ingestion process complete."
