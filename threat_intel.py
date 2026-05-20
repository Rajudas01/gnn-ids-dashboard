import requests

# =====================================================
# ABUSE IPDB API CONFIG
# =====================================================

API_KEY = "77a4b32891f9ee7c1c12da36304ddd1b2e98ce9e7b92f35430ee30e06011ce0b7460c4d973eedd13"

BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# =====================================================
# CHECK IP REPUTATION
# =====================================================

def check_ip_reputation(ip_address):

    try:

        headers = {
            "Key": API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }

        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params
        )

        if response.status_code == 200:

            data = response.json()

            return data["data"]

        else:

            return {
                "error": f"API Error: {response.status_code}"
            }

    except Exception as e:

        return {
            "error": str(e)
        }