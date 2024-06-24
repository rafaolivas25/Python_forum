from datetime import datetime, timedelta
from flask import current_app
from itsdangerous import URLSafeTimedSerializer as Serializer
from forum.extensions import db, login_manager
from flask_login import UserMixin


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(40), unique=True, nullable=False)
    client_secret = db.Column(db.String(55), nullable=False)
    redirect_uri = db.Column(db.String(200), nullable=False)
    scope = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuthorizationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(255), unique=True, nullable=False)
    client_id = db.Column(db.String(40), nullable=False)
    scope = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=10))


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(255), unique=True, nullable=False)
    refresh_token = db.Column(db.String(255), unique=True, nullable=False)
    client_id = db.Column(db.String(40), nullable=False)
    scope = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=1))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='topic', lazy=True, cascade="all, delete-orphan")
    user = db.relationship('User', backref='topics')

    def __repr__(self):
        return f"Topic('{self.title}', '{self.date_created}')"


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=False)
    user = db.relationship('User', backref='messages')

    def __repr__(self):
        return f"Message('{self.content}', '{self.date_posted}')"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(100), nullable=True)
    mfa_otp = db.Column(db.Boolean, default=False)
    mfa_security_questions = db.Column(db.Boolean, default=False)
    mfa_hardware_key = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32), nullable=True)
    security_question_1 = db.Column(db.String(200), nullable=True)
    security_answer_1 = db.Column(db.String(200), nullable=True)
    security_question_2 = db.Column(db.String(200), nullable=True)
    security_answer_2 = db.Column(db.String(200), nullable=True)
    hardware_key_public = db.Column(db.String(200), nullable=True)
    hardware_key_private = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(20), nullable=False, default='user')
    last_login = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

    def has_role(self, role_name):
        return self.role == role_name
