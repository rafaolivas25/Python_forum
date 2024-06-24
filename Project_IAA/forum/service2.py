from flask import Flask, redirect, request, session, url_for, jsonify, render_template
import requests

app = Flask(__name__)
app.secret_key = 'service2_secret_key'

client_id = 'service2_client_id'
client_secret = 'service2_client_secret'
authorization_base_url = 'http://localhost:5000/oauth/authorize'
token_url = 'http://localhost:5000/oauth/token'
redirect_uri = 'http://localhost:5002/callback'
login_url = 'http://localhost:5000/login'


@app.route('/')
def home():
    return render_template('service2.html')


@app.route('/login')
def login():
    authorization_url = f'{authorization_base_url}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope=read'
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    code = request.args.get('code')
    response = requests.post(token_url, data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret
    })
    token = response.json()
    session['access_token'] = token['access_token']
    return redirect(url_for('.protected_resource'))


@app.route('/protected_resource')
def protected_resource():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('.login'))

    return redirect(login_url)


if __name__ == '__main__':
    app.run(port=5002)
