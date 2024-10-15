from models import User
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError

class Signupform(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('role', choices=[('user', 'User'), ('admin', 'Admin')], validate_choice=[DataRequired()])
    submit = SubmitField('Sign up')

    def validate_username(self, field):
        username = field.data
        user = User.query.filter_by(username=username).first()
        if user:
            raise ValidationError("Username is already taken.")
        
class Loginform(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Login')