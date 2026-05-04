import os
import requests
from dotenv import load_dotenv

# Load the keys from your .env file
load_dotenv()

def check_abuse_ip(ip_address):
    """
    Checks an IP address against the AbuseIPDB database.
    Returns a dictionary with a calculated risk level.
    """
    api_key = os.getenv("ABUSEIPDB_KEY")
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90' 
    }

    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)
        
        if response.status_code == 200:
            data = response.json()['data']
            score = data['abuseConfidenceScore']
            
            # --- Forensic Risk Logic ---
            if score == 0:
                risk = "CLEAN"
            elif score < 50:
                risk = "SUSPICIOUS"
            else:
                risk = "MALICIOUS"

            return {
                "ip": data['ipAddress'],
                "abuse_score": score,
                "risk_level": risk,          # New field added
                "total_reports": data['totalReports'],
                "country": data['countryCode'],
                "usage_type": data['usageType']
            }
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# --- Quick Test ---
if __name__ == "__main__":
    # Test with a known IP
    test_ip = "193.163.125.43"
    result = check_abuse_ip(test_ip)
    
    if result:
        print(f"\n--- Results for {result['ip']} ---")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Abuse Confidence Score: {result['abuse_score']}%")
        print(f"Total Reports: {result['total_reports']}")
        print(f"Country Code: {result['country']}")