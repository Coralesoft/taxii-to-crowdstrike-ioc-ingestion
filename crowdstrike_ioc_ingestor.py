import requests
from cabby import create_client

# CrowdStrike Falcon API credentials
# Replace these placeholders with your actual Falcon API credentials.
CLIENT_ID = 'your_client_id'
CLIENT_SECRET = 'your_client_secret'

# TAXII server credentials and URL
# Replace these placeholders with your actual TAXII server credentials and collection.
TAXII_SERVER_URL = 'https://taxii.server.url'
TAXII_USERNAME = 'your_taxii_username'
TAXII_PASSWORD = 'your_taxii_password'
TAXII_COLLECTION = 'your_taxii_collection'

# Function to get OAuth2 token from CrowdStrike Falcon
def get_crowdstrike_token(client_id, client_secret):
    # API endpoint for obtaining OAuth2 tokens
    auth_url = "https://api.crowdstrike.com/oauth2/token"
    
    # Data payload containing the client credentials
    auth_data = {
        'client_id': client_id,
        'client_secret': client_secret
    }

    # Sending a POST request to the Falcon API to retrieve an access token
    response = requests.post(auth_url, data=auth_data)

    # Checking if the response was successful (status code 200)
    if response.status_code == 200:
        # Parse the JSON response to extract the access token
        return response.json()['access_token']
    else:
        # Print error message if the request failed
        print(f"Error fetching token: {response.status_code} {response.text}")
        return None

# Function to query the TAXII server and get STIX objects
def get_stix_objects():
    # Create a TAXII client using the provided server URL
    client = create_client(TAXII_SERVER_URL)
    
    # Authenticate the client using TAXII server credentials
    client.set_auth(username=TAXII_USERNAME, password=TAXII_PASSWORD)
    
    # Log message indicating the collection being polled
    print(f"Polling collection: {TAXII_COLLECTION}")

    # Poll the TAXII collection and retrieve STIX objects
    stix_objects = client.poll(collection_name=TAXII_COLLECTION)
    
    # Initialize an empty list to hold IOCs (Indicators of Compromise)
    iocs = []

    # Loop through the blocks of STIX objects returned by the TAXII server
    for block in stix_objects:
        print(f"STIX Object: {block}")  # Log each STIX block
        for obj in block.content.objects:
            # If the STIX object is of type 'indicator', process it
            if obj['type'] == 'indicator':
                # Transform the STIX object into a CrowdStrike-compatible IOC
                ioc_data = transform_stix_to_ioc(obj)
                if ioc_data:
                    # Add the transformed IOC to the list
                    iocs.append(ioc_data)

    # Return the list of IOCs after processing all STIX objects
    return iocs

# Function to transform STIX indicators to CrowdStrike IOC format
def transform_stix_to_ioc(stix_indicator):
    ioc_type = None  # Placeholder for the type of IOC (domain, IP, file hash, etc.)
    pattern = stix_indicator.get('pattern', '')  # Extract the pattern from the STIX object

    # Check if the pattern represents a domain
    if 'domain-name' in pattern:
        ioc_type = 'domain'  # Set IOC type to 'domain'
        value = pattern.split("'")[1]  # Extract the domain value from the pattern string
    
    # Check if the pattern represents an IPv4 address
    elif 'ipv4-addr' in pattern:
        ioc_type = 'ipv4'  # Set IOC type to 'ipv4'
        value = pattern.split("'")[1]  # Extract the IP address from the pattern string

    # Check if the pattern represents a file hash (SHA-256)
    elif 'file:hashes' in pattern:
        ioc_type = 'sha256'  # Set IOC type to 'sha256'
        value = pattern.split("'")[1]  # Extract the hash value from the pattern string
    
    # If the pattern doesn't match any known IOC type, print a warning
    else:
        print(f"Unsupported STIX pattern: {pattern}")
        return None

    # Return a dictionary representing the IOC in CrowdStrike's expected format
    return {
        "type": ioc_type,  # The type of IOC (e.g., domain, ipv4, sha256)
        "value": value,  # The actual IOC value (e.g., domain name, IP address, hash)
        "action": "detect",  # Action to take on the IOC ('detect', 'prevent', or 'both')
        "source": "TAXII Import"  # The source label for tracking IOCs from this import
    }

# Function to push the transformed IOCs to CrowdStrike Falcon
def push_iocs_to_crowdstrike(iocs, token):
    # CrowdStrike API endpoint for IOC ingestion
    ioc_url = "https://api.crowdstrike.com/indicators/entities/iocs/v1"
    
    # Set up the headers for the API request, including the OAuth2 access token
    headers = {
        'Authorization': f'Bearer {token}',  # Include the Bearer token in the Authorization header
        'Content-Type': 'application/json'  # Specify that the request payload is in JSON format
    }

    # Loop through each IOC in the list of transformed IOCs
    for ioc in iocs:
        print(f"Pushing IOC to CrowdStrike: {ioc}")  # Log the IOC being pushed
        
        # Send a POST request to the CrowdStrike API to ingest the IOC
        response = requests.post(ioc_url, headers=headers, json=ioc)

        # Check if the IOC was successfully ingested (status code 201)
        if response.status_code == 201:
            print(f"IOC successfully pushed: {ioc}")  # Log success message
        else:
            # Log an error message if the request failed
            print(f"Error pushing IOC: {response.status_code} {response.text}")

# Main function to run the script
def main():
    # Get an OAuth2 access token from CrowdStrike Falcon
    token = get_crowdstrike_token(CLIENT_ID, CLIENT_SECRET)
    
    # If the token is None (failure), exit the script
    if not token:
        return

    # Retrieve IOCs from the TAXII server and process them
    iocs = get_stix_objects()
    
    # If there are any IOCs, push them to CrowdStrike
    if iocs:
        push_iocs_to_crowdstrike(iocs, token)

# Execute the main function when the script is run
if __name__ == "__main__":
    main()
