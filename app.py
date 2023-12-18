from flask import Flask, redirect, request, session, url_for
import requests
from urllib.parse import urlencode
from google.oauth2.id_token import verify_oauth2_token
from google.auth.transport.requests import Request

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
        return f'Hello, {user_info["name"]}! <a href="/logout">Logout</a> | <a href="/new-feature">New Feature</a>'
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
    print(f"Received Authorization Code: {code}")
    token = get_access_token(code)

    # Debugging output
    print(f"Received Authorization Code: {code}")
    print(f"Obtained Access Token: {token}")
    print(f"Access Token before calling get_user_info: {token}")
    #id_token = get_access_token(code)
    user_info = get_user_info(token)
    #user_info = get_user_info(token)
    print(f"User Info from Google: {user_info}")

    try:
        # Verify the ID token
        print("enter try_before id")
        id_info = verify_oauth2_token(token, Request(), app.config['GOOGLE_CLIENT_ID'])
        print(f"try pass id: {id_info}")



        # 在这里提取你需要的信息，例如用户ID、过期时间等
        user_id = id_info.get('sub')
        expires_at = id_info.get('exp')
        print(f"try pass user_id: {user_id}")
        print(f"try pass expires_at: {expires_at}")

        # 将用户ID和过期时间存储在 session 中或进行其他处理
        session['user_id'] = user_id
        session['expires_at'] = expires_at
        #print(f"try pass id: {id_info}")
        #print(f"try pass id: {id_info}")

        # 如果需要进行更多的验证，可以在这里添加逻辑
        # ...

        # 如果一切正常，将用户重定向到 home 页面
        return redirect(url_for('home'))

    except Exception as e:
        print(f"try except Error verifying ID token: {e}")
        print("try except Failed to authenticate with Google")

        # Add this line to print the received ID token
        id_token = token
        print(f"try except Received ID Token: {id_token}")

        return 'Failed to authenticate with Google try except'


@app.route('/new-feature')
def new_feature():
    if 'google_token' in session:
        # 获取已登录用户的 token
        user_token = session['google_token']

        # 示例：进行授权请求，你可以根据实际情况修改 API 地址和参数
        #api_url = 'https://api.example.com/new-feature-endpoint'
        api_url = 'https://www.linkedin.com/in/xinyuanfucn/'
        result = make_authorized_request(api_url, user_token)

        if result:
            return f'New Feature: {result}'
        else:
            return 'new feature Failed to make authorized request. def new_featire'

    return redirect(url_for('login'))

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
    print(f"Token Request Response: {response.text}") 
    token_response = response.json()
    return token_response.get('access_token')  # 从响应中提取 ID Token，而不是 Access Token
    #return token_response.get('ya29.a0AfB_byAkBY-xVY9ThVXMO9WFw4Cp5bAg1qZFqHtoW_ZZVjeffDoUHeqDyXqxUedPi2905xolBXJ5rX5OkcfqZV38jlgzTR-xP-52ArmIL2_ty-SBkfmKNkKbHqsiAtRp_jt6ikGb9kZP_Jb1TrJv5pv5hW1FmHTkqU9YaCgYKATgSARISFQHGX2Mirfkw5qoBm1DRL7XayXM9kg0171')


def get_user_info(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(app.config['GOOGLE_USER_INFO_URL'], headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        # 输出调试信息
        print(f"Failed to get user info. Status code: {response.status_code}")
        print(response.text)
        return response.json()

def make_authorized_request(api_url, token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return response.text  # 这里可以根据实际情况修改返回的结果
    else:
        # 输出调试信息
        print(f"Failed to make authorized request. make_authorized_request Status code: {response.status_code}")
        print(response.text)
        return None

if __name__ == '__main__':
    from urllib.parse import urlencode
    app.run(debug=True, host='0.0.0.0', port=5000)