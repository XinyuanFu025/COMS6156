from flask import Flask, redirect, request, session, url_for
import requests
import json
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'ashduihibfdshui' #your_secret_key
app.config['GOOGLE_CLIENT_ID'] = '671071079747-0mr2lmq57gnn2vn9sk06hpvolg6m3msp.apps.googleusercontent.com'
app.config['GOOGLE_CLIENT_SECRET'] = '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'
app.config['GOOGLE_REDIRECT_URI'] = 'http://34.16.183.53.nip.io:8000/callback'
app.config['GOOGLE_AUTH_URL'] = 'https://accounts.google.com/o/oauth2/auth'
app.config['GOOGLE_TOKEN_URL'] = 'https://accounts.google.com/o/oauth2/token'
app.config['GOOGLE_USER_INFO_URL'] = 'https://www.googleapis.com/oauth2/v1/userinfo'

@app.route('/')

def home():
    if 'google_token' in session:
        user_info = get_user_info(session['google_token'])

        # Check if 'name' key exists in user_info
        if 'name' in user_info:
            username = user_info['name']
        else:
            username = 'User'

        return f'Hello, {username}! <a href="/logout">Logout</a>'
    else:
        return '<a href="/login">Login with Google</a>'

#def home():
#    if 'google_token' in session:
#        user_info = get_user_info(session['google_token'])
#        return f'Hello, {user_info["name"]}! <a href="/logout">Logout</a>'
#    else:
#        return '<a href="/login">Login with Google</a>'

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
    session['google_token'] = token
    return redirect(url_for('home'))

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
    return response.json()

if __name__ == '__main__':
    from urllib.parse import urlencode
    #app.run(debug=True, port=8080)
    app.run(debug=True, host='0.0.0.0', port=8080)
