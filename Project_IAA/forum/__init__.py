import os
import smtplib

from flask import Flask, current_app
from logging.handlers import RotatingFileHandler

from .extensions import db, mail, login_manager, bcrypt
from .models import User
import logging


def test_smtp_connection():
    try:
        server = smtplib.SMTP(current_app.config['MAIL_SERVER'], current_app.config['MAIL_PORT'])
        server.ehlo()
        if current_app.config['MAIL_USE_TLS']:
            server.starttls()
        server.login(current_app.config['MAIL_USERNAME'], current_app.config['MAIL_PASSWORD'])
        server.quit()
        current_app.logger.debug("SMTP connection successful.")
    except Exception as e:
        current_app.logger.error(f"Failed to connect to SMTP server: {e}")


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'your_secret_key'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///site.db'),
        MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
        MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
        MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1'],
        MAIL_USERNAME=os.environ.get('MAIL_USERNAME', 'your-email@gmail.com'),
        MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD', 'your-email-password')
    )

    # Set up logging
    handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.DEBUG)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.DEBUG)

    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)

    from forum.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from forum.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from forum.routes import oauth as oauth_blueprint
    app.register_blueprint(oauth_blueprint, url_prefix='/oauth')

    return app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
