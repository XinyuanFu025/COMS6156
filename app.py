from flask import Flask, redirect, url_for, session
from flask_oauthlib.client import OAuth

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Update the callback URL to match your GCP VM's IP or domain
MANUAL_CALLBACK_URL = 'http://34.125.89.250:5000/login/authorized'

oauth = OAuth(app)

google = oauth.remote_app(
    'google',
    consumer_key='671071079747-1er03q01u8nab6v7o7oq81ao591ms4gl.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email https://www.googleapis.com/auth/userinfo.email openid',
    },
    base_url='https://www.googleapis.com/plus/v1/',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
)

@app.route('/')
def index():
    return 'Welcome to the Flask SSO Example. <a href="/login">Login with Google</a>'

@app.route('/login')
def login():
    return google.authorize(callback=MANUAL_CALLBACK_URL)

@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return 'Logged out successfully.'

@app.route('/login/authorized')
def authorized():
    response = google.authorized_response()
    app.logger.info('OAuth Response: %s', response)
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    
    session['google_token'] = (response['access_token'], '')
    user_info = google.get('people/me')
    return 'Logged in as: ' + user_info.data['displayName']

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
