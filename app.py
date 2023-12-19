from flask import Flask, redirect, request, session, url_for
import requests
import json
from urllib.parse import urlencode
from flask import jsonify

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

@app.route('/api/protected_data')
def protected_data():
    # 这里可以是一些虚构的受保护数据
    data = {"message": "This is protected data!"}
    return jsonify(data)

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

    if response.status_code == 200:
        return response.json()
    else:
        # 输出调试信息
        print(f"Failed to get user info. Status code: {response.status_code}")
        print(response.text)
        return None

@app.route('/protected_resource')
def protected_resource():
    if 'google_token' in session:
        token = session['google_token']
        user_info = get_user_info(token)
        
        # 在这里你可以使用 token 向受保护资源发起请求
        # 例如，假设有一个示例的受保护资源 URL
        #protected_resource_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
        #protected_resource_url = 'http://34.125.89.250:5000/api/protected_data'
        protected_resource_url = 'http://54.82.84.92:8080/'
        response = make_protected_request(protected_resource_url, token)
        
        # 处理受保护资源的响应
        if response.status_code == 200:
            return f'Hello, {user_info["name"]}! Protected resource response: {response.json()} <a href="/logout">Logout</a>'
        else:
            return f'Error accessing protected resource. Status code: {response.status_code}'

    else:
        return '<a href="/login">Login with Google</a>'
    
def make_protected_request(url, token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    return response
    

if __name__ == '__main__':
    from urllib.parse import urlencode
    app.run(debug=True, host='0.0.0.0', port=5000)