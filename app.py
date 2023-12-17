from flask import Flask, redirect, request, session, url_for
import requests
from google.auth import jwt
from google.auth.exceptions import GoogleAuthError
import json

app = Flask(__name__)
app.secret_key = 'abcdefg'
app.config['GOOGLE_CLIENT_ID'] = '671071079747-1er03q01u8nab6v7o7oq81ao591ms4gl.apps.googleusercontent.com'
app.config['GOOGLE_CLIENT_SECRET'] = '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'
app.config['GOOGLE_REDIRECT_URI'] = 'http://34.125.89.250.nip.io:5000/callback'
app.config['GOOGLE_AUTH_URL'] = 'https://accounts.google.com/o/oauth2/auth'
app.config['GOOGLE_TOKEN_URL'] = 'https://accounts.google.com/o/oauth2/token'
app.config['GOOGLE_USER_INFO_URL'] = 'https://www.googleapis.com/oauth2/v1/userinfo'

@app.route('/')
def home():
    if 'google_token' in session:
        user_info = get_user_info(session['google_token'])
        return f'Hello, {user_info["name"]}! <a href="/logout">Logout</a>'
    else:
        return '<a href="/login">Login with Google</a>'

@app.route('/login')
def login():
    return redirect(get_auth_url())

@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('home'))

@app.route('/callback')
def callback():
    code = request.args.get('code')
    token = get_access_token(code)

    # Debugging output
    print(f"Received Authorization Code: {code}")
    print(f"Obtained Access Token: {token}")

    if token:
        # Decode and verify the JWT token
        id_info = decode_verify_jwt(token)
        print(f"Decoded JWT Token: {id_info}")

        if id_info:
            session['google_token'] = token
            return redirect(url_for('home'))

    # Output additional information in case of failure
    print("Failed to authenticate with Google")
    print(f"Full Request: {request.url}")
    return 'Failed to authenticate with Google'


def get_auth_url():
    params = {
        'client_id': app.config['GOOGLE_CLIENT_ID'],
        'redirect_uri': app.config['GOOGLE_REDIRECT_URI'],
        'scope': 'openid profile email',
        'response_type': 'code',
    }
    return f"{app.config['GOOGLE_AUTH_URL']}?{urlencode(params)}"

def get_access_token(code):
    data = {
        'code': code,
        'client_id': app.config['GOOGLE_CLIENT_ID'],
        'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri': app.config['GOOGLE_REDIRECT_URI'],
        'grant_type': 'authorization_code',
    }
    response = requests.post(app.config['GOOGLE_TOKEN_URL'], data=data)
    return response.json().get('access_token')

def get_user_info(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(app.config['GOOGLE_USER_INFO_URL'], headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        # Output debug information
        print(f"Failed to get user info. Status code: {response.status_code}")
        print(response.text)
        return None

def decode_verify_jwt(token):
    try:
        decoded_token = jwt.decode(token, verify=False)
        # You can add verification logic here if needed
        return decoded_token
    #except jwt.ExpiredSignatureError:
    #    print("JWT token has expired.")
    #    return None
    #except jwt.JWTError as e:
    #    print(f"Error decoding JWT token: {e}")
    #    return None
    except GoogleAuthError as e:
        print(f"Error decoding JWT token: {e}")
        return None

if __name__ == '__main__':
    from urllib.parse import urlencode
    app.run(debug=True, host='0.0.0.0', port=5000)
