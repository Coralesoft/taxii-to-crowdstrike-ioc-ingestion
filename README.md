
# TAXII to CrowdStrike IOC Ingestion Script

This repository contains two versions (Python and Shell) of a script designed to poll a **STIX/TAXII** server for **Indicators of Compromise (IOCs)** and ingest them into **CrowdStrike Falcon**. The scripts handle **pagination**, **token management**, and include **robust error handling** for interacting with both TAXII and CrowdStrike Falcon APIs.

## Features
- Poll **STIX/TAXII** servers to retrieve IOCs.
- Push or update **IOCs** into **CrowdStrike Falcon**.
- Handle **pagination** for large datasets from both TAXII and CrowdStrike Falcon APIs.
- **Retry mechanism** for transient failures (network issues).
- Supports setting API credentials via environment variables for secure deployment.
- **Expiration management** for IOCs (valid for 3 months by default).

## Contents
- `taxii_to_crowdstrike.sh` - Shell version of the script.
- `taxii_to_crowdstrike.py` - Python version of the script.

## Requirements

### Shell Version (`taxii_to_crowdstrike.sh`):
- **Bash** (tested with `/bin/sh`)
- `curl` for making HTTP requests.
- `jq` for parsing JSON responses.

### Python Version (`taxii_to_crowdstrike.py`):
- **Python 3.6+**
- `requests` library for handling HTTP requests.
- `jq` equivalent for processing JSON in Python (parsing handled by the `requests` library).

You can install the Python dependencies with:
\`\`\`bash
pip install requests
\`\`\`

## Usage

### Environment Variables

Both versions of the script expect the following environment variables to be set:

| Variable            | Description                               |
|---------------------|-------------------------------------------|
| `CLIENT_ID`         | CrowdStrike Falcon API client ID          |
| `CLIENT_SECRET`     | CrowdStrike Falcon API client secret      |
| `TAXII_SERVER_URL`  | URL of the TAXII server                   |
| `TAXII_USERNAME`    | TAXII server username                     |
| `TAXII_PASSWORD`    | TAXII server password                     |
| `TAXII_COLLECTION`  | TAXII collection name                     |

### Running the Shell Version

To execute the shell script, ensure it's executable and run it as follows:

\`\`\`bash
chmod +x taxii_to_crowdstrike.sh
./taxii_to_crowdstrike.sh
\`\`\`

### Running the Python Version

Make sure you have Python 3 installed. Then, execute the Python script:

\`\`\`bash
python3 taxii_to_crowdstrike.py
\`\`\`

### Logging

Both versions of the script log all activity to a log file located at `/var/log/taxii_to_crowdstrike.log` by default. You can modify this log path in the script if needed.

## Script Overview

### Shell Version (`taxii_to_crowdstrike.sh`):
This version of the script is a **Bash**-based implementation that uses `curl` for HTTP requests and `jq` for JSON parsing.

Main functions:
- **get_crowdstrike_token**: Fetches the OAuth2 token from CrowdStrike Falcon.
- **poll_taxii_server**: Polls the TAXII server for IOCs, handling pagination if necessary.
- **push_iocs_to_crowdstrike**: Pushes IOCs to CrowdStrike Falcon, either creating new entries or updating existing ones.

### Python Version (`taxii_to_crowdstrike.py`):
This version of the script is implemented in **Python**, leveraging the `requests` library for HTTP interactions and parsing JSON directly.

Main functions:
- **get_crowdstrike_token**: Fetches the OAuth2 token from CrowdStrike Falcon.
- **poll_taxii_server**: Polls the TAXII server for IOCs and handles pagination.
- **check_ioc_exists_paginated**: Checks if an IOC already exists in CrowdStrike, handling pagination.
- **push_iocs_to_crowdstrike**: Pushes or updates IOCs in CrowdStrike Falcon.

## Version History

| Version      | Date         | Notes                                                             |
|--------------|--------------|-------------------------------------------------------------------|
| **2024.10.1**| 08-10-2024    | Initial Public Release                                            |
| **2024.10.2**| 09-10-2024    | Added error handling, logging, and retries for robustness         |
| **2024.10.3**| 09-10-2024    | Handle pagination of large datasets from TAXII and CrowdStrike    |
| **2024.10.4**| 09-10-2024    | Improved token handling, error checking, and page-by-page processing |

## License

This software is released under the **MIT License**. See the [LICENSE](LICENSE) file for the full license text.

