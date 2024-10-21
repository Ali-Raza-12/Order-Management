from models import User, Orders, Products, OrderItem
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, IntegerField, FloatField, FieldList, FormField, DecimalField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError, NumberRange

# class CreateUserForm(FlaskForm): 
#     username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
#     password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])
#     confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
#     role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])

#     def validate_username(self, field):
#         username = field.data
#         user = User.query.filter_by(username=username).first()
#         if user:
#             raise ValidationError('Username already exists.')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, field):
        username = field.data
        user = User.query.filter_by(username=username).first()
        if user:
            raise ValidationError("Username is already taken.")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OrderItemForm(FlaskForm):
    product_id = SelectField('Product', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])


class OrderForm(FlaskForm):
    shipping_address = StringField('Shipping Address', validators=[DataRequired()])
    note = TextAreaField('Note')
    discount = FloatField('Discount', default=0.00)
    total_payable = FloatField('Total Payable', validators=[DataRequired()])
    paid_amount = FloatField('Paid Amount', validators=[DataRequired()])
    due_amount = FloatField('Due Amount', validators=[DataRequired()])
    status = SelectField('Status', choices=[('Pending', 'Pending'), ('Completed', 'Completed')], validators=[DataRequired()])
    order_items = FieldList(FormField(OrderItemForm), min_entries=1)

class AddProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0)])
    stock = IntegerField('Stock', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Add Product')
