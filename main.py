import requests
import sys
from base64 import b64encode


def authenticate(client_id, client_secret, pbx_address):
    token_url = f"https://{pbx_address}/apis/oauth2/token"
    credentials_base64 = b64encode(f"{client_id}:{client_secret}".encode()).decode('utf-8')
    headers = {
        'Authorization': f'Basic {credentials_base64}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    try:
        response = requests.post(token_url, data={'grant_type': 'client_credentials'}, headers=headers)
        if response.status_code == 401:
            print("Authentication failed. Wrong username and/or password.")
            return None
        response.raise_for_status()
        access_token = response.json().get('access_token')
        return access_token
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"Error occurred: {err}")
    return None


def get_acd_stats(access_token, pbx_address):
    acd_stats_url = f"https://{pbx_address}/apis/pbx/v1/acd/stats?agents=false&calls=true&relative=true"
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        response = requests.get(acd_stats_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"Error occurred: {err}")
    return None


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python main.py <client_id> <client_secret> <pbx_address>")
        sys.exit(1)
    client_id, client_secret, pbx_address = sys.argv[1:4]
    access_token = authenticate(client_id, client_secret, pbx_address)
    if access_token:
        acd_stats = get_acd_stats(access_token, pbx_address)
        if acd_stats:
            print(acd_stats)
    else:
        print("Authentication failed. Exiting now...")
