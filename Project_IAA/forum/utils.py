import smtplib

import pyotp
from flask import current_app
from flask_mail import Message
from forum.extensions import mail
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from forum.models import User

import logging

logger = logging.getLogger(__name__)


def generate_otp_secret():
    secret = pyotp.random_base32()
    current_app.logger.debug(f'Generated OTP secret: {secret}')
    return secret


def get_totp(secret):
    return pyotp.TOTP(secret)


def send_otp_email(user):
    if not user.otp_secret:
        raise ValueError("User does not have an OTP secret.")

    totp = pyotp.TOTP(user.otp_secret)
    otp_code = totp.now()
    logger.debug(f"Generated OTP code: {otp_code}")

    try:
        msg = Message("Your OTP Code",
                      sender=current_app.config['MAIL_USERNAME'],
                      recipients=[user.email])
        msg.body = f"Your OTP code is: {otp_code}"
        mail.send(msg)
        logger.debug(f"OTP email sent to user: {user.email}")
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication error: {e}")
    except smtplib.SMTPServerDisconnected as e:
        logger.error(f"SMTP server disconnected: {e}")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")


def verify_totp(user: User, otp_code: str) -> bool:
    """
    Verify the OTP code for a given user.

    Args:
        user (User): The user object.
        otp_code (str): The OTP code to verify.

    Returns:
        bool: True if the OTP code is valid, False otherwise.
    """
    current_app.logger.debug(f'Verifying OTP for user {user.email} with code {otp_code}')
    if not user.otp_secret:
        raise ValueError("User does not have an OTP secret.")
    totp = pyotp.TOTP(user.otp_secret)
    result = totp.verify(otp_code)
    current_app.logger.debug(f'OTP verification result for user {user.email}: {result}')
    return result


def save_user_to_db(user):
    """Save the user to the database."""
    from forum.extensions import db
    db.session.add(user)
    db.session.commit()


def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


def get_public_key_pem(private_key):
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem.decode('utf-8')


def generate_signature(private_key, data):
    """Generate a signature for the given data using the private key."""
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_hardware_key_signature(public_key_pem, signature, data):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False
