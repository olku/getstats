import requests
import sys
from base64 import b64encode

'''
pip install dependencies with 'pip install -r requirements.txt', then run as:
python main.py <client_id> <client_secret> <pbx_address>
'''


def authenticate(client_id, client_secret, pbx_address):
    token_url = f"https://{pbx_address}/apis/oauth2/token"

    credentials = f"{client_id}:{client_secret}"
    credentials_base64 = b64encode(credentials.encode()).decode('utf-8')
    auth_header = {'Authorization': f'Basic {credentials_base64}'}

    client_credentials = {
        'grant_type': 'client_credentials'
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }

    response = requests.post(token_url, data=client_credentials, headers={**headers, **auth_header})
    if response.status_code == 200:
        access_token = response.json().get('access_token')
        return access_token
    else:
        print(f"Authentication failed. Status code: {response.status_code}")
        print(response.text)
        return None


def get_acd_stats(access_token, pbx_address):
    acd_stats_url = f"https://{pbx_address}/apis/pbx/v1/acd/stats?agents=false&calls=true&relative=true"
    headers = {'Authorization': f'Bearer {access_token}'}

    response = requests.get(acd_stats_url, headers=headers)
    if response.status_code == 200:
        acd_stats = response.json()
        return acd_stats
    else:
        print(f"Failed to get ACD stats. Status code: {response.status_code}")
        print(response.text)
        return None


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python main.py <client_id> <client_secret> <pbx_address>")
        sys.exit(1)

    client_id = sys.argv[1]
    client_secret = sys.argv[2]
    pbx_address = sys.argv[3]

    access_token = authenticate(client_id, client_secret, pbx_address)

    if access_token:
        print("Authentication successful!")

        acd_stats = get_acd_stats(access_token, pbx_address)

        if acd_stats:
            print("ACD Stats:", acd_stats)
