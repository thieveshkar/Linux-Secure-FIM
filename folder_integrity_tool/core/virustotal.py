# Developed by: thieveshkar_cb013248
#
# VirusTotal Scanner module.
# Handles API queries and rate limiting gracefully.

import requests
from core.utils import VT_API_KEY

class VirusTotalScanner:
    """
    Handles interactions with the VirusTotal v3 API.
    Provides robust handling for rate limiting and network faults.
    """
    def __init__(self, api_key=VT_API_KEY):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/files/"

    def scan_hash(self, file_hash):
        """
        Queries VirusTotal for a given SHA-256 hash.
        Elegantly handles quota limits (HTTP 429).
        """
        if not self.api_key or self.api_key.strip() == "" or self.api_key == "":
            return "VT Verdict: [API Key Not Configured]"

        headers = {"x-apikey": self.api_key}

        try:
            url = f"{self.base_url}{file_hash}"
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 429:
                return "VT Verdict: [API Rate Limit Reached - Verification Pending]"
            elif response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                return f"VT Verdict Score: {malicious}/{total}"
            elif response.status_code == 404:
                return "VT Verdict: [Hash Not Found]"
            else:
                return f"VT Verdict: [Error {response.status_code}]"

        except requests.exceptions.RequestException as e:
            return f"VT Verdict: [Network Error - {str(e)}]"
