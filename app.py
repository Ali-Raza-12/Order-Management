from flask import Flask, render_template, flash, redirect, url_for, jsonify, request
from models import User, bcrypt, db
from forms import Signupform, Loginform
from config import Config
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager, decode_token
from datetime import timedelta

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
jwt = JWTManager(app)

@app.route('/')
def home():
    is_authenticated, current_user = get_authenticated_user()
    return render_template('home.html', is_authenticated=is_authenticated, current_user=current_user)

def get_authenticated_user():
    current_user = None
    is_authenticated = False
    try:
        access_token = request.cookies.get('access_token')
        if access_token:
            decoded_token = decode_token(access_token, allow_expired=False)
            current_user = decoded_token['sub']  
            is_authenticated = True
        else:
            flash("No token found in cookie.", 'warning')
    except Exception as e:
        print(f'Error in getting current user: {e}')
    
    return is_authenticated, current_user

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = Signupform()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  
            flash('An error occurred while creating your account. Please try again.', 'danger')
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity={'username': user.username, 'role': user.role}, expires_delta=timedelta(days=1))
            flash('Login successful', 'success')
            response = redirect(url_for('home'))
            response.set_cookie('access_token', access_token, httponly=True)  # Store JWT token in a cookie
            return response
        else:
            flash('Login unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    flash('You have been logged out.', 'info')
    response = redirect(url_for('login'))
    response.delete_cookie('access_token')
    return response

# @app.route('/admin-dashboard')
# @jwt_required()
# def admin_dashboard():
#     current_user = get_jwt_identity()
#     if current_user['role'] != 'admin':
#         return jsonify({"msg": "Admins only!"}), 403
#     return render_template('admin_dashboard.html', user=current_user)

@app.route('/user-dashboard', methods=['GET'])
def user_dashboard():
    access_token = request.cookies.get('access_token')
    is_authenticated = True
    if not access_token:
        return jsonify({"msg": "Missing Authorized Header"}), 401
    
    try:
        current_user = decode_token(access_token)
    except Exception as e:
        return jsonify({"msg": str(e)}), 401  
    
    users = User.query.all()
    return render_template('dashboard.html', current_user=current_user, users=users, is_authenticated=is_authenticated)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run(debug=True)
