from flask import Flask, request, jsonify
import requests
import json
import os
import jwt
from dotenv import load_dotenv
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

load_dotenv()

app = Flask(__name__)

# GCP Configuration
WORKFORCE_POOL_ID = os.getenv("WORKFORCE_POOL_ID")
WORKFORCE_PROVIDER_ID = os.getenv("WORKFORCE_PROVIDER_ID")
PROJECT_NUMBER = os.getenv("PROJECT_NUMBER")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
SEARCH_CONFIG_ID = os.getenv("SEARCH_CONFIG_ID")
FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")

print(WORKFORCE_POOL_ID)
print(WORKFORCE_PROVIDER_ID)
print(PROJECT_NUMBER)

def int_to_base64(value):
    """Convert an integer to a base64url-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('ascii')

def generate_key_pair():
    """Generate RSA key pair and return private key and JWK"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Get public key numbers
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    # Create JWK from public key
    jwk = {
        'kid': '1',
        'kty': 'RSA',
        'n': int_to_base64(public_numbers.n),
        'e': int_to_base64(public_numbers.e),
    }

    return private_pem, jwk

# Generate or load keys
PRIVATE_KEY, PUBLIC_JWK = generate_key_pair()

# Print JWK for GCP configuration
print("Public JWK for GCP configuration:")
print(json.dumps({'keys': [PUBLIC_JWK]}, indent=2))

def modify_index():
    with open('static/index.html.template', 'r') as file:
        data = file.read()
        data = data.replace('SEARCH_CONFIG_ID', SEARCH_CONFIG_ID)
        data = data.replace('FACEBOOK_APP_ID', FACEBOOK_APP_ID)
    with open('static/index.html', 'w') as file:
        file.write(data)

modify_index()
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/jwk.json')
def get_public_key():
    print('###########################################################################################')
    return json.dumps(PUBLIC_JWK)


def get_facebook_user_info(fb_token):
    """Facebook Graph API를 통해 사용자 정보 조회"""
    fb_url = 'https://graph.facebook.com/me'
    params = {
        'fields': 'id,name,email',
        'access_token': fb_token
    }
    response = requests.get(fb_url, params=params)
    print("facebook_user_info")
    print(response)
    if response.status_code != 200:
        raise Exception('Failed to get Facebook user info')
    return response.json()

def create_jwt_token(user_info):
    """사용자 정보로 JWT 토큰 생성"""
    now = datetime.datetime.now()
    headers = {
        'alg': 'RS256',
        'typ': 'JWT',
        'kid': '1',
        'jku': 'https://b4ae-124-56-24-46.ngrok-free.app/jwk.json',
        #'jwk': PUBLIC_JWK
    }
    payload = {
        'sub': f"{user_info['email']}",
        'name': user_info['name'],
        'iss': 'https://www.facebook.com',
        'aud': '883530703950819', # f'//iam.googleapis.com/locations/global/workforcePools/{WORKFORCE_POOL_ID}/providers/{WORKFORCE_PROVIDER_ID}',
        'iat': int(now.timestamp()),
        'exp': int((now + datetime.timedelta(hours=2)).timestamp())
    }
    print('iat')
    print(payload['iat'])
    encoded_jwt = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256', headers=headers)  
    print("encoded_jwt")
    print(encoded_jwt)
    return encoded_jwt

def verify_jwt_token(jwt_token):
    try:
        decoded_payload = jwt.decode(jwt_token, JWT_SECRET_KEY, algorithms=['RS256'])
        print("Valid signature")
        print("Decoded Payload:", decoded_payload)
        return True, decoded_payload
    except jwt.ExpiredSignatureError:
        print("Signature has expired")
        return False, None
    except jwt.InvalidSignatureError:
        print("Invalid signature")
        return False, None
    except jwt.DecodeError:
         print("Decode error")
         return False, None
    except Exception as e:
        print(f"Other error: {e}")
        return False, None

@app.route('/get_gcp_token', methods=['POST'])
def get_gcp_token():
    try:
        fb_token = request.json.get('fb_token')
        if not fb_token:
            return jsonify({'error': 'Facebook token is required'}), 400

        # 1. Facebook 사용자 정보 조회
        try:
            user_info = get_facebook_user_info(fb_token)
        except Exception as e:
            return jsonify({'error': f'Failed to get Facebook user info: {str(e)}'}), 400

        # 2. JWT 토큰 생성
        jwt_token = create_jwt_token(user_info)
        # is_verified, decoded_payload = verify_jwt_token(jwt_token)
        # if not is_verified:
        #     return jsonify({'error': 'JWT token verification failed'}), 400

        # STS token exchange endpoint
        sts_url = 'https://sts.googleapis.com/v1/token'

        print(jwt_token)
        # Prepare the request payload
        payload = {
            'audience': f'//iam.googleapis.com/locations/global/workforcePools/{WORKFORCE_POOL_ID}/providers/{WORKFORCE_PROVIDER_ID}',
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'scope': 'https://www.googleapis.com/auth/cloud-platform',
            'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',  # For Facebook JWT
            'subject_token': jwt_token,
            'options': json.dumps({
                'userProject': PROJECT_NUMBER
            })
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(sts_url, data=payload, headers=headers)

        print(response)
        if response.status_code == 200:
            token_data = response.json()
            return jsonify({'token': token_data.get('access_token')})
        else:
            return jsonify({'error': f'Token exchange failed: {response.text}'}), response.status_code

    except Exception as e:
        print (e)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)