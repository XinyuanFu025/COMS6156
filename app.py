from flask import Flask, redirect, request, session, url_for
from google.auth.jwt import decode as google_jwt_decode
import requests
from google.auth import jwt
from google.auth.exceptions import GoogleAuthError
from google.auth.jwt import decode as jwt_decode
import json
import jwt

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

    
    try:
        # Verify the ID token
        id_info = verify_oauth2_token(token, Request(), 671071079747-1er03q01u8nab6v7o7oq81ao591ms4gl.apps.googleusercontent.com)

        # 在这里提取你需要的信息，例如用户ID、过期时间等
        user_id = id_info.get('sub')
        expires_at = id_info.get('exp')

        # 将用户ID和过期时间存储在 session 中或进行其他处理
        session['user_id'] = user_id
        session['expires_at'] = expires_at

        # 如果需要进行更多的验证，可以在这里添加逻辑
        # ...

        # 如果一切正常，将用户重定向到 home 页面
        return redirect(url_for('home'))

    except Exception as e:
        print(f"Error verifying ID token: {e}")
        print("Failed to authenticate with Google")
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
        # Output the raw token for debugging
        print(f"Raw JWT Token: {token}")

        # Attempt to decode the token
        decoded_token = jwt.decode(token, verify=False)

        return decoded_token
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
    except jwt.InvalidTokenError:
        print("Invalid token.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return None

if __name__ == '__main__':
    from urllib.parse import urlencode
    app.run(debug=True, host='0.0.0.0', port=5000)
