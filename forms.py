# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User

# A custom validator to check if a username or email already exists in the database
class UniqueCheck:
    def __init__(self, model, field, message=None):
        self.model = model
        self.field = field
        if not message:
            message = 'This item already exists.'
        self.message = message

    def __call__(self, form, field):
        check = self.model.query.filter(self.field == field.data).first()
        if check:
            raise ValidationError(self.message)

class RegistrationForm(FlaskForm):
    # Field definitions and required validators
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20),
                                       UniqueCheck(User, User.username, message='That username is taken.')])
    email = StringField('Email',
                        validators=[DataRequired(), Email(),
                                    UniqueCheck(User, User.email, message='That email is already in use.')])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me') # <--- NEW: For persistent session
    submit = SubmitField('Log In')