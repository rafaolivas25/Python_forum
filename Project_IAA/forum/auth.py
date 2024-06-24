import logging
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from flask import Blueprint, request, jsonify, render_template, session, flash, redirect, url_for, current_app
from flask_login import login_user, current_user, logout_user, login_required

from forum import db, bcrypt
from forum.forms import OTPForm, RegistrationForm, LoginForm, SelectMFAForm, \
    SecurityQuestionsForm, UpdateAccountForm, VerifyHardwareKeyForm, AssignRoleForm
from forum.models import User, AuthorizationCode
from forum.utils import generate_private_key, verify_hardware_key_signature
from forum.utils import get_public_key_pem, generate_signature
from forum.utils import send_otp_email, verify_totp, generate_otp_secret
from flask import send_file
import jwt
from datetime import datetime, timedelta
from forum.models import Token, db
from flask import current_app
import random
import string

logger = logging.getLogger(__name__)

auth = Blueprint('auth', __name__)

rp = PublicKeyCredentialRpEntity("example.com", "Example App")
server = Fido2Server(rp)


def generate_authorization_code(client_id, scope):
    code = ''.join(random.choices(string.ascii_letters + string.digits, k=30))
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    authorization_code = AuthorizationCode(client_id=client_id, code=code, scope=scope, expires_at=expires_at)
    db.session.add(authorization_code)
    db.session.commit()
    return code


def generate_token(client_id, scope):
    access_token = ''.join(random.choices(string.ascii_letters + string.digits, k=30))
    refresh_token = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
    expires_at = datetime.utcnow() + timedelta(minutes=60)
    token = Token(client_id=client_id, access_token=access_token, refresh_token=refresh_token, scope=scope,
                  expires_at=expires_at)
    db.session.add(token)
    db.session.commit()
    return access_token, refresh_token


def verify_token(token_str):
    token = Token.query.filter_by(access_token=token_str).first()
    if token and token.expires_at > datetime.utcnow():
        return token
    return None


def generate_hardware_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode('utf-8'), public_pem.decode('utf-8')


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        if form.validate():
            logger.debug(f'Registration form submitted with data: {form.data}')
            otp_secret = generate_otp_secret() if form.mfa_method.data == 'otp' else None

            # Inicializa as variáveis para as chaves
            public_key_pem = None
            private_key_pem = None

            # Geração do par de chaves RSA somente se hardware_key for selecionado
            if form.mfa_method.data == 'hardware_key':
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

            user = User(
                username=form.username.data,
                email=form.email.data,
                password=bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
                phone_number=form.phone_number.data,
                address=form.address.data,
                otp_secret=otp_secret,
                mfa_otp=form.mfa_method.data == 'otp',
                mfa_security_questions=form.mfa_method.data == 'security_questions',
                mfa_hardware_key=form.mfa_method.data == 'hardware_key',
                security_question_1=form.security_question_1.data,
                security_answer_1=form.security_answer_1.data,
                security_question_2=form.security_question_2.data,
                security_answer_2=form.security_answer_2.data,
                hardware_key_public=public_key_pem.decode('utf-8') if public_key_pem else None,
                hardware_key_private=private_key_pem.decode('utf-8') if private_key_pem else None,
                role='user'
            )
            db.session.add(user)
            try:
                db.session.commit()
                logger.debug(f'User {user.username} registered successfully.')

                if form.mfa_method.data == 'hardware_key':
                    flash('Your account has been created! Please copy your private key.', 'success')
                    return render_template('display_private_key.html', private_key=private_key_pem.decode('utf-8'))
                else:
                    flash('Your account has been created! You are now able to log in.', 'success')
                    return redirect(url_for('auth.login'))

            except Exception as e:
                logger.error(f'Error committing user {user.username} to the database: {e}')
                db.session.rollback()
                flash('An error occurred while creating your account. Please try again.', 'danger')
        else:
            logger.debug(f'Registration form errors: {form.errors}')
            flash('Please correct the errors in the form and try again.', 'danger')

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
                try:
                    send_otp_email(user)  # envio do email OTP
                    logger.debug(f'OTP email sent to user: {user.email}')
                except Exception as e:
                    logger.error(f'Failed to send OTP email: {e}')
                    flash('An error occurred while sending the OTP. Please try again.', 'danger')
                    return redirect(url_for('auth.login'))
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


@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/assign_role', methods=['GET', 'POST'])
@auth.route('/assign_role', methods=['GET', 'POST'])
@login_required
def assign_role():
    current_app.logger.debug(f'Current user: {current_user}')
    current_app.logger.debug(f'Is admin: {current_user.is_admin}')

    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.home'))

    form = AssignRoleForm()
    if form.validate_on_submit():
        email = form.email.data
        role = form.role.data
        user = User.query.filter_by(email=email).first()
        if user:
            user.role = role
            user.is_admin = (role == 'admin')
            db.session.commit()
            flash('Role assigned successfully.', 'success')
        else:
            flash('User not found.', 'danger')

    return render_template('assign_role.html', form=form)


@auth.route('/verify_otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    user = User.query.get(user_id)
    form = OTPForm()

    if request.method == 'POST':
        current_app.logger.info(f'POST request received at verify_otp for user: {user.email}')
        if form.validate_on_submit():
            otp_code = form.otp_code.data
            current_app.logger.info(f'OTP code submitted: {otp_code}')
            current_app.logger.debug(f'User OTP secret: {user.otp_secret}')
            current_app.logger.debug(f'Calling verify_totp with user: {user}, otp_code: {otp_code}')
            try:
                if verify_totp(user, otp_code):
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                    flash('OTP verified successfully.', 'success')
                    return redirect(url_for('main.home'))
                else:
                    flash('Invalid OTP code. Please try again.', 'danger')
                    current_app.logger.debug(f'Invalid OTP code entered for user: {user.email}')
            except Exception as e:
                current_app.logger.error(f'Error verifying OTP: {e}')
        else:
            current_app.logger.debug('Form validation failed.')

    if request.method == 'GET':
        current_app.logger.info(f'GET request received at verify_otp for user: {user.email}')
        send_otp_email(user)
        current_app.logger.debug(f'Sent OTP email to user: {user.email}')

    return render_template('verify_otp.html', title='Verify OTP', user_id=user_id, form=form)


@auth.route('/verify_security_questions/<int:user_id>', methods=['GET', 'POST'])
def verify_security_questions(user_id):
    user = User.query.get(user_id)
    if not user:
        logger.error(f'User with ID {user_id} not found.')
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))

    form = SecurityQuestionsForm()
    if form.validate_on_submit():
        logger.debug(f'Verify security questions form submitted with data: {form.data}')
        logger.debug(f'User answers in DB: {user.security_answer_1}, {user.security_answer_2}')
        logger.debug(f'Provided answers: {form.security_answer_1.data}, {form.security_answer_2.data}')

        # Verifique as respostas das perguntas de segurança
        if (form.security_answer_1.data == user.security_answer_1 and
                form.security_answer_2.data == user.security_answer_2):
            logger.debug(f'Security questions verified successfully for user: {user.email}')
            # Login bem-sucedido, redirecione para a página principal
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('main.home'))
        else:
            logger.debug(f'Invalid security answers for user: {user.email}')
            flash('Security answers are incorrect. Please try again.', 'danger')

    logger.debug(f'Rendering security questions verification form for user: {user.email}')
    return render_template('verify_security_questions.html', title='Verify Security Questions', form=form)


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
        elif mfa_method == 'hardware_key':
            return redirect(url_for('auth.register_key'))
    return render_template('select_mfa.html', form=form)


def verify_hardware_key_signature(public_key_pem, signature, data):
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification error: {e}")
        return False


@auth.route('/verify_hardware_key/<int:user_id>', methods=['GET', 'POST'])
@login_required
def verify_hardware_key(user_id):
    form = VerifyHardwareKeyForm()
    user = User.query.get_or_404(user_id)

    if form.validate_on_submit():
        private_key_pem = form.private_key.data.encode('utf-8')
        data = form.data.data.encode('utf-8')

        # Carregar a chave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

        # Assinar os dados
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Verificar a assinatura com a chave pública do usuário
        public_key_pem = user.hardware_key_public.encode('utf-8')
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            flash('Hardware key verified successfully!', 'success')
            return redirect(url_for('main.home'))
        except Exception as e:
            flash('Hardware key verification failed.', 'danger')
            logger.debug(f'Hardware key verification error: {e}')

    return render_template('verify_hardware_key.html', form=form, user_id=user_id)


# Função auxiliar para assinar os dados simuladamente
def sign_data(data):
    private_key_pem = session.get('private_key')
    if not private_key_pem:
        raise Exception("No private key found in session.")
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None,
                                                     backend=default_backend())
    signature = generate_signature(private_key, data)
    return signature


@auth.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('auth.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)
