from wtforms import PasswordField, BooleanField, TextAreaField
from wtforms.fields.choices import RadioField, SelectField
from wtforms.fields.form import FormField
from wtforms.validators import Email, EqualTo, ValidationError

from forum import bcrypt
from forum.models import User
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Optional


class SecurityQuestionsForm(FlaskForm):
    security_question_1 = StringField('Security Question 1', validators=[DataRequired()])
    security_answer_1 = StringField('Answer 1', validators=[DataRequired()])
    security_question_2 = StringField('Security Question 2', validators=[DataRequired()])
    security_answer_2 = StringField('Answer 2', validators=[DataRequired()])
    submit = SubmitField('Verify')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone_number = StringField('Phone Number')
    address = StringField('Address')
    mfa_method = SelectField('MFA Method',
                             choices=[('none', 'None'), ('otp', 'OTP'), ('security_questions', 'Security Questions'),
                                      ('hardware_key', 'Hardware Key')])
    security_question_1 = StringField('Security Question 1', validators=[Optional()])
    security_answer_1 = StringField('Answer 1', validators=[Optional()])
    security_question_2 = StringField('Security Question 2', validators=[Optional()])
    security_answer_2 = StringField('Answer 2', validators=[Optional()])
    hardware_key_public = StringField('Hardware Key Public')
    submit = SubmitField('Sign Up')

    def validate(self):
        if not FlaskForm.validate(self):
            return False
        if self.mfa_method.data == 'security_questions':
            if not self.security_question_1.data or not self.security_answer_1.data:
                self.security_question_1.errors.append('This field is required.')
                self.security_answer_1.errors.append('This field is required.')
                return False
            if not self.security_question_2.data or not self.security_answer_2.data:
                self.security_question_2.errors.append('This field is required.')
                self.security_answer_2.errors.append('This field is required.')
                return False
        return True

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class AssignRoleForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Assign Role')


class TopicForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    submit = SubmitField('Create Topic')


class MessageForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post Message')


class SelectMFAForm(FlaskForm):
    mfa_method = RadioField('MFA Method', choices=[('otp', 'OTP'), ('security_questions', 'Security Questions')],
                            default='otp')
    submit = SubmitField('Continue')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class OTPForm(FlaskForm):
    otp_code = StringField('OTP Code', validators=[DataRequired()])
    submit = SubmitField('Verify')


class RoleAssignmentForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = StringField('Role', validators=[DataRequired()])
    submit = SubmitField('Assign Role')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password')
    confirm_new_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password')])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

    def validate_current_password(self, current_password):
        if current_password.data:
            if not bcrypt.check_password_hash(current_user.password, current_password.data):
                raise ValidationError('Current password is incorrect.')


class VerifySecurityQuestionsForm(FlaskForm):
    security_answer_1 = StringField('Answer 1', validators=[DataRequired(), Length(max=200)])
    security_answer_2 = StringField('Answer 2', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('Verify Answers')


class VerifyHardwareKeyForm(FlaskForm):
    private_key = TextAreaField('Private Key', validators=[DataRequired()])
    data = TextAreaField('Data to Sign', validators=[DataRequired()])
    submit = SubmitField('Verify')
