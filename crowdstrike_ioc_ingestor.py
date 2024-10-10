#!/usr/bin/env python3
# TAXII to CrowdStrike IOC Ingestion Script
# Script to poll a STIX/TAXII server for IOCs and ingest them into CrowdStrike Falcon.
# Developed by C.Brown (dev@coralesoft.nz)
# This software is released under the MIT License.
# See the LICENSE file in the project root for the full license text.
# Last revised 10/10/2024
# version 2024.10.5
#-----------------------------------------------------------------------
# Version      Date         Notes:
# 2024.10.1    08-10.2024   Initial Public Release
# 2024.10.2    09.10.2024   Added error handling, logging, and retries for robustness
# 2024.10.3    09.10.2024   Handle pagination of large datasets
# 2024.10.4    09.10.2024   Added improved token handling, error checking, and page-by-page processing
# 2024.10.5    10.10.2024   Added configurable rate limiting
#-----------------------------------------------------------------------

import os
import requests
import logging
import time
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta

# Configure logging
LOG_FILE = '/var/log/taxii_to_crowdstrike.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Load API credentials from environment variables or default values
CLIENT_ID = os.getenv('CLIENT_ID', 'your_client_id')
CLIENT_SECRET = os.getenv('CLIENT_SECRET', 'your_client_secret')
TAXII_SERVER_URL = os.getenv('TAXII_SERVER_URL', 'https://taxii.server.url')
TAXII_USERNAME = os.getenv('TAXII_USERNAME', 'your_taxii_username')
TAXII_PASSWORD = os.getenv('TAXII_PASSWORD', 'your_taxii_password')
TAXII_COLLECTION = os.getenv('TAXII_COLLECTION', 'your_taxii_collection')

# Rate limiting delay (in seconds) configurable via environment variable, default is 2 seconds
RATE_LIMIT_DELAY = int(os.getenv('RATE_LIMIT_DELAY', 2))

MAX_RETRIES = 3

def log(message):
    """Log message to file and console."""
    logging.info(message)
    print(message)

def retry(func, *args, **kwargs):
    """Retry function with exponential backoff."""
    n = 1
    delay = 5
    while n <= MAX_RETRIES:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log(f"Command failed. Attempt {n}/{MAX_RETRIES}. Retrying in {delay} seconds...")
            time.sleep(delay)
            n += 1
            delay *= 2
    log("The command has failed after maximum retry attempts.")
    return None

def rate_limit():
    """Rate limiting to control the request frequency."""
    log(f"Rate limiting: Waiting for {RATE_LIMIT_DELAY} seconds before the next request...")
    time.sleep(RATE_LIMIT_DELAY)

def get_crowdstrike_token():
    """Retrieve CrowdStrike OAuth2 token."""
    log("Fetching CrowdStrike OAuth2 token...")
    url = 'https://api.crowdstrike.com/oauth2/token'
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(url, data=data)
    if response.status_code == 200:
        access_token = response.json().get('access_token')
        log("CrowdStrike OAuth2 token acquired.")
        return access_token
    else:
        log(f"Failed to get OAuth2 token: {response.status_code} {response.text}")
        return None

def poll_taxii_server():
    """Poll TAXII server and handle pagination."""
    log(f"Polling TAXII server at {TAXII_SERVER_URL} for collection {TAXII_COLLECTION}...")
    headers = {'Content-Type': 'application/xml'}
    auth = HTTPBasicAuth(TAXII_USERNAME, TAXII_PASSWORD)
    next_token = None
    all_iocs = []

    while True:
        data = f"<taxii_poll_request_xml{' next=' + next_token if next_token else ''}/>"
        response = requests.post(f"{TAXII_SERVER_URL}/collections/{TAXII_COLLECTION}/poll", headers=headers, auth=auth, data=data)
        
        if response.status_code != 200:
            log(f"Failed to poll TAXII server: {response.status_code} {response.text}")
            break

        taxii_data = response.json()
        iocs = [obj['pattern'].split("'")[1] for obj in taxii_data.get('objects', []) if obj['type'] == 'indicator']
        all_iocs.extend(iocs)
        log(f"Retrieved {len(iocs)} IOCs from TAXII.")
        
        # Add rate limiting between each request
        rate_limit()

        next_token = taxii_data.get('next_token')
        if not next_token:
            break

    return all_iocs

def check_ioc_exists_paginated(ioc_value, access_token):
    """Check if IOC exists in CrowdStrike Falcon, handle pagination."""
    url = f"https://api.crowdstrike.com/indicators/queries/iocs/v1?value={ioc_value}"
    headers = {'Authorization': f'Bearer {access_token}'}
    next_token = None

    while True:
        if next_token:
            response = requests.get(f"{url}&next_token={next_token}", headers=headers)
        else:
            response = requests.get(url, headers=headers)

        if response.status_code != 200:
            log(f"Failed to check IOC: {response.status_code} {response.text}")
            return False

        if response.json().get('resources'):
            return True

        next_token = response.json().get('meta', {}).get('pagination', {}).get('next_token')
        if not next_token:
            break

    return False

def calculate_expiration_date():
    """Calculate expiration date for IOC (3 months from now)."""
    expiration_date = datetime.utcnow() + timedelta(days=90)
    return expiration_date.strftime('%Y-%m-%dT%H:%M:%SZ')

def push_iocs_to_crowdstrike(iocs, access_token):
    """Push or update IOCs in CrowdStrike Falcon."""
    log("Pushing or updating IOCs in CrowdStrike Falcon...")
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    
    for ioc in iocs:
        log(f"Processing IOC: {ioc}")
        expiration_date = calculate_expiration_date()

        if check_ioc_exists_paginated(ioc, access_token):
            log(f"IOC {ioc} already exists. Updating...")
            payload = {
                "type": "domain",
                "value": ioc,
                "action": "detect",
                "valid_until": expiration_date,
                "source": "TAXII Import"
            }
            response = requests.patch("https://api.crowdstrike.com/indicators/entities/iocs/v1", headers=headers, json=payload)
        else:
            log(f"IOC {ioc} is new. Adding...")
            payload = {
                "type": "domain",
                "value": ioc,
                "action": "detect",
                "valid_until": expiration_date,
                "source": "TAXII Import"
            }
            response = requests.post("https://api.crowdstrike.com/indicators/entities/iocs/v1", headers=headers, json=payload)

        if response.status_code not in (200, 201):
            log(f"Failed to push/update IOC {ioc}: {response.status_code} {response.text}")
        
        # Add rate limiting between each IOC push
        rate_limit()

def main():
    log("TAXII to CrowdStrike IOC ingestion started.")
    access_token = retry(get_crowdstrike_token)
    
    if not access_token:
        log("Failed to obtain access token. Exiting.")
        return
    
    iocs = retry(poll_taxii_server)
    
    if iocs:
        retry(push_iocs_to_crowdstrike, iocs, access_token)
    
    log("IOC ingestion and management process complete.")

if __name__ == '__main__':
    main()
