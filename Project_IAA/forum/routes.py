import pyotp
from forum.forms import OTPForm, RoleAssignmentForm, UpdateAccountForm, SelectMFAForm, MessageForm, TopicForm
from forum.utils import get_totp, generate_otp_secret, send_otp_email, verify_totp
from forum.decorators import role_required
from flask import Blueprint, render_template, url_for, flash, redirect, request, current_app
from flask_login import login_user, current_user, logout_user, login_required
from forum import db, bcrypt
from forum.models import User, Topic, Message
from forum.forms import RegistrationForm, LoginForm, OTPForm, SecurityQuestionsForm
from forum.utils import send_otp_email, verify_totp, generate_otp_secret, save_user_to_db
from datetime import datetime
from flask import Blueprint, request, jsonify, redirect, url_for
from forum.models import Client, Token, AuthorizationCode
from forum.auth import generate_token, verify_token, generate_authorization_code
from flask import Blueprint, request, jsonify, redirect, url_for, render_template, session

main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)
oauth = Blueprint('oauth', __name__)


from flask import Blueprint, request, jsonify, redirect, url_for, render_template
from forum.models import Client, Token, AuthorizationCode
from forum.auth import generate_token, verify_token, generate_authorization_code

oauth = Blueprint('oauth', __name__)

@oauth.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'POST':
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        response_type = request.form.get('response_type')
        scope = request.form.get('scope')
        state = request.form.get('state')

        client = Client.query.filter_by(client_id=client_id).first()
        if client:
            code = generate_authorization_code(client_id, scope)
            return redirect(f'{redirect_uri}?code={code}&state={state}')
        return jsonify({'error': 'Invalid client'}), 400
    else:
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope')
        state = request.args.get('state')
        return render_template('authorize.html', client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state)

@oauth.route('/token', methods=['POST'])
def token():
    grant_type = request.form.get('grant_type')
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        authorization_code = AuthorizationCode.query.filter_by(code=code).first()
        if authorization_code:
            access_token, refresh_token = generate_token(authorization_code.client_id, authorization_code.scope)
            return jsonify({'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'Bearer', 'expires_in': 3600})
        return jsonify({'error': 'Invalid authorization code'}), 400
    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        token = Token.query.filter_by(refresh_token=refresh_token).first()
        if token:
            access_token, new_refresh_token = generate_token(token.client_id, token.scope)
            return jsonify({'access_token': access_token, 'refresh_token': new_refresh_token, 'token_type': 'Bearer', 'expires_in': 3600})
        return jsonify({'error': 'Invalid refresh token'}), 400
    return jsonify({'error': 'Unsupported grant type'}), 400

@oauth.route('/userinfo', methods=['GET'])
def userinfo():
    token = request.headers.get('Authorization').split()[1]
    user = verify_token(token)
    if user:
        return jsonify({'sub': user['client_id'], 'scope': user['scope']})
    return jsonify({'error': 'Invalid token'}), 401


@main.route("/")
@main.route("/home")
@login_required
def home():
    topics = Topic.query.all()
    return render_template('home.html', topics=topics)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        otp_secret = pyotp.random_base32()
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
            otp_secret=otp_secret,
            role='user',
            last_login=None
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', title='Register', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if user.mfa_otp:
                send_otp_email(user)
                return redirect(url_for('auth.verify_otp', user_id=user.id))
            elif user.mfa_security_questions:
                return redirect(url_for('auth.verify_security_questions', user_id=user.id))
            elif user.mfa_hardware_key:
                return redirect(url_for('auth.verify_hardware_key', user_id=user.id))
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            current_app.logger.debug('Login failed for user: {}'.format(form.email.data))
    return render_template('login.html', title='Login', form=form)


@main.route('/topic/new', methods=['GET', 'POST'])
@login_required
def new_topic():
    form = TopicForm()
    if form.validate_on_submit():
        topic = Topic(title=form.title.data, user_id=current_user.id)
        db.session.add(topic)
        db.session.commit()
        flash('Your topic has been created!', 'success')
        return redirect(url_for('main.home'))
    return render_template('create_topic.html', title='New Topic', form=form)


@main.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
@login_required
def topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(content=form.content.data, user_id=current_user.id, topic_id=topic.id)
        db.session.add(message)
        db.session.commit()
        flash('Your message has been posted!', 'success')
        return redirect(url_for('main.topic', topic_id=topic.id))
    messages = Message.query.filter_by(topic_id=topic.id).all()
    return render_template('topic.html', title=topic.title, topic=topic, form=form, messages=messages)


@auth.route("/select_mfa", methods=['GET', 'POST'])
@login_required
def select_mfa():
    form = SelectMFAForm()
    if form.validate_on_submit():
        mfa_method = form.mfa_method.data
        user_id = current_user.id
        if mfa_method == 'otp':
            send_otp_email(current_user)  # Send the OTP
            return redirect(url_for('auth.verify_otp', user_id=user_id))
        elif mfa_method == 'security_questions':
            return redirect(url_for('auth.verify_security_questions', user_id=user_id))
        elif mfa_method == 'key':
            return redirect(url_for('auth.register_key'))  # New route for registering a key
    return render_template('select_mfa.html', form=form)


@auth.route('/verify_otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    user = User.query.get(user_id)
    form = OTPForm()

    if request.method == 'POST':
        current_app.logger.info('POST request received at verify_otp for user: {}'.format(user.email))
        if form.validate_on_submit():
            otp_code = form.otp_code.data
            current_app.logger.info('OTP code submitted: {}'.format(otp_code))
            current_app.logger.debug(f'User OTP secret: {user.otp_secret}')
            current_app.logger.debug('Calling verify_totp with user: {}, otp_code: {}'.format(user, otp_code))
            if verify_totp(user, otp_code):
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash('OTP verified successfully.', 'success')
                return redirect(url_for('main.home'))
            else:
                flash('Invalid OTP code. Please try again.', 'danger')
                current_app.logger.debug('Invalid OTP code entered for user: {}'.format(user.email))
        else:
            current_app.logger.debug('Form validation failed.')

    if request.method == 'GET':
        current_app.logger.info('GET request received at verify_otp for user: {}'.format(user.email))
        send_otp_email(user)
        current_app.logger.debug('Sent OTP email to user: {}'.format(user.email))

    return render_template('verify_otp.html', title='Verify OTP', user_id=user_id, form=form)


@auth.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route("/assign_role", methods=['GET', 'POST'])
@login_required
@role_required('admin')  # Only admins can assign roles
def assign_role():
    form = RoleAssignmentForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            user.role = form.role.data
            db.session.commit()
            flash(f'Role {form.role.data} has been assigned to {user.username}.', 'success')
        else:
            flash('User not found.', 'danger')
    return render_template('assign_role.html', title='Assign Role', form=form)


@auth.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.current_password.data:
            if bcrypt.check_password_hash(current_user.password, form.current_password.data):
                hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                current_user.password = hashed_password
            else:
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('auth.account'))
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('auth.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account Settings', form=form)


@auth.route("/set_security_questions", methods=['GET', 'POST'])
@login_required
def set_security_questions():
    form = SecurityQuestionsForm()
    if form.validate_on_submit():
        current_user.security_question_1 = form.security_question_1.data
        current_user.security_answer_1 = bcrypt.generate_password_hash(form.security_answer_1.data).decode('utf-8')
        current_user.security_question_2 = form.security_question_2.data
        current_user.security_answer_2 = bcrypt.generate_password_hash(form.security_answer_2.data).decode('utf-8')
        db.session.commit()
        flash('Your security questions have been set!', 'success')
        return redirect(url_for('main.home'))
    return render_template('set_security_questions.html', title='Set Security Questions', form=form)


@auth.route('/verify_security_questions/<int:user_id>', methods=['GET', 'POST'])
@login_required
def verify_security_questions(user_id):
    user = User.query.get(user_id)
    form = SecurityQuestionsForm()

    current_app.logger.debug(f"Serving verify_security_questions for user_id: {user_id}")
    current_app.logger.debug(f"User: {user}")

    if request.method == 'POST':
        current_app.logger.debug(f"Received POST request with form data: {form.data}")

        if form.validate_on_submit():
            current_app.logger.debug("Form validation successful.")
            current_app.logger.debug(
                f"Security Question 1: {form.security_question_1.data}, Expected: {user.security_question_1}")
            current_app.logger.debug(
                f"Security Answer 1: {form.security_answer_1.data}, Expected: {user.security_answer_1}")
            current_app.logger.debug(
                f"Security Question 2: {form.security_question_2.data}, Expected: {user.security_question_2}")
            current_app.logger.debug(
                f"Security Answer 2: {form.security_answer_2.data}, Expected: {user.security_answer_2}")

            if (user.security_question_1 == form.security_question_1.data and
                    user.security_answer_1 == form.security_answer_1.data and
                    user.security_question_2 == form.security_question_2.data and
                    user.security_answer_2 == form.security_answer_2.data):
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash('Security questions verified successfully.', 'success')
                current_app.logger.debug("Security questions verified successfully.")
                return redirect(url_for('main.home'))
            else:
                flash('Invalid answers. Please try again.', 'danger')
                current_app.logger.debug("Invalid answers. Please try again.")
        else:
            current_app.logger.debug(f"Form validation errors: {form.errors}")

    return render_template('verify_security_questions.html', title='Verify Security Questions', form=form)
