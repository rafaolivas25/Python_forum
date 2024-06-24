from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_login import LoginManager

db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()
login_manager = LoginManager()

login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'
