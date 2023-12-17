from flask import Flask, redirect, request, session, url_for
import requests
from urllib.parse import urlencode

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
        return f'Hello, {user_info["name"]}! <a href="/logout">Logout</a><br>' \
               f'<a href="/feature1">Feature 1</a><br>' \
               f'<a href="/feature2">Feature 2</a><br>' \
               f'<a href="/feature3">Feature 3</a>'
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
    session['google_token'] = token
    return redirect(url_for('home'))

@app.route('/feature1')
def feature1():
    if 'google_token' in session:
        # 使用令牌进行授权请求（示例）
        authorized_data = make_authorized_request('https://www.googleapis.com/some/api/feature1', session['google_token'])
        return f'Feature 1 Data: {authorized_data}'
    else:
        return 'Unauthorized'

@app.route('/feature2')
def feature2():
    # 类似地，处理 Feature 2 的逻辑
    pass

@app.route('/feature3')
def feature3():
    # 类似地，处理 Feature 3 的逻辑
    pass

# ...

if __name__ == '__main__':
    from urllib.parse import urlencode
    app.run(debug=True, host='0.0.0.0', port=5000)
