import requests, redis, os
from dotenv import load_dotenv

redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Save the hash to the Redis whitelist if it's safe
def save_hash_to_redis(file_hash):
    # print("Hash have been added to redis")
    redis_client.setex(f"safe_hash:{file_hash}", 2592000, "safe")

# Check the hash in the Redis whitelist.
def is_hash_in_whitelist(file_hash):
    return redis_client.exists(f"safe_hash:{file_hash}")

load_dotenv("config\\config.env")
API_KEY = os.getenv("API_KEY")

def get_api_key():
    return API_KEY

def check_virustotal(file_hash):
    # Verify the hash in Redis initially.
    if is_hash_in_whitelist(file_hash):
        # print("Hash is already in Redis")
        return 0

    # Load API Key
    api_key = get_api_key()
    api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        if response.status_code == 200:
            result = response.json()
            malicious_count = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)

            if malicious_count <= 3:
                save_hash_to_redis(file_hash)
            return malicious_count
        # If not found in Virustotal
        elif response.status_code == 404:
            # print("Hash does not have in VirusTotal")   
            return 0
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return 0
    except requests.exceptions.Timeout:
        print(f"Timeout occurred while connecting to the server when checking value ({file_hash})")
        return 0
    except requests.exceptions.RequestException as e:
        print(f"An error occurred when checking value ({file_hash}): {e}")
        return 0
