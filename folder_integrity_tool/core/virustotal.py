# Developed by: thieveshkar_cb013248
#
# VirusTotal Scanner module.
# Handles API queries and rate limiting gracefully.

# Import the 'requests' library, which is used to send HTTP requests to web servers (like the VirusTotal API)
import requests
# Import the VirusTotal API key that we stored in our utils file
from core.utils import VT_API_KEY

# Define a class (a blueprint for creating objects) to handle VirusTotal scanning
class VirusTotalScanner:
    """
    Handles interactions with the VirusTotal v3 API.
    Provides robust handling for rate limiting and network faults.
    """
    # This is the initialization method that runs when we create a new VirusTotalScanner object
    def __init__(self, api_key=VT_API_KEY):
        # Store the API key inside the object so it can be used later
        self.api_key = api_key
        # Define the base web address (URL) for the VirusTotal API file scanning endpoint
        self.base_url = "https://www.virustotal.com/api/v3/files/"

    # Define a method to scan a file's hash (a unique digital fingerprint of the file)
    def scan_hash(self, file_hash):
        """
        Queries VirusTotal for a given SHA-256 hash.
        Elegantly handles quota limits (HTTP 429).
        """
        # Check if the API key is missing, empty, or just spaces
        if not self.api_key or self.api_key.strip() == "" or self.api_key == "":
            # If the API key is not valid, return a message saying it's not configured
            return "VT Verdict: [API Key Not Configured]"

        # Create the headers dictionary, which sends the API key securely to the server
        headers = {"x-apikey": self.api_key}

        try:
            # Combine the base URL and the file hash to create the exact web address to query
            url = f"{self.base_url}{file_hash}"
            # Send an HTTP GET request to the VirusTotal server, and wait at most 10 seconds for a reply
            response = requests.get(url, headers=headers, timeout=10)

            # Check if the server responded with status code 429 (Too Many Requests / Rate Limit Reached)
            if response.status_code == 429:
                # Return a message indicating we have hit the query limit and should wait
                return "VT Verdict: [API Rate Limit Reached - Verification Pending]"
            # Check if the server responded with status code 200 (OK / Success)
            elif response.status_code == 200:
                # Convert the server's response from JSON text into a Python dictionary
                data = response.json()
                # Extract the scanning statistics from the dictionary safely using .get()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                # Get the number of antivirus engines that flagged this file as 'malicious' (default is 0)
                malicious = stats.get("malicious", 0)
                # Calculate the total number of engines that scanned the file by adding all the values
                total = sum(stats.values())
                # Return the final score showing how many engines found it malicious out of the total
                return f"VT Verdict Score: {malicious}/{total}"
            # Check if the server responded with status code 404 (Not Found)
            elif response.status_code == 404:
                # Return a message saying VirusTotal has never seen this file before
                return "VT Verdict: [Hash Not Found]"
            # If any other status code is returned (like 500 Server Error)
            else:
                # Return a general error message with the status code
                return f"VT Verdict: [Error {response.status_code}]"

        # If something goes wrong with the network connection (e.g., no internet, timeout)
        except requests.exceptions.RequestException as e:
            # Return a message describing the network error
            return f"VT Verdict: [Network Error - {str(e)}]"
