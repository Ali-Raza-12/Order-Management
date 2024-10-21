from flask import Flask, render_template, flash, redirect, url_for, jsonify, request
from models import User, bcrypt, db, Orders, Products, OrderItem
from forms import SignupForm, LoginForm, OrderForm, AddProductForm, OrderItemForm
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
    except Exception as e:
        print(f'Error in getting current user: {e}')
    
    return is_authenticated, current_user

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    is_authenticated, current_user = get_authenticated_user()
    if is_authenticated:
        return redirect(url_for('home'))
    
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data, 
            password=hashed_password, 
            role=form.role.data,
            created_by=None,  
            updated_by=None  
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(e) 
            flash('An error occurred while creating your account. Please try again.', 'danger')
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    is_authenticated, current_user = get_authenticated_user()
    if is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity={'username': user.username, 'role': user.role}, expires_delta=timedelta(days=1))
            flash('Login successful', 'success')
            response = redirect(url_for('home'))
            response.set_cookie('access_token', access_token, httponly=True) 
            return response
        else:
            flash('Login unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    flash('You have been logged out.', 'info')
    response = redirect(url_for('home'))
    response.delete_cookie('access_token')
    return response

@app.route('/customers')
def customers():
    is_authenticated, current_user = get_authenticated_user()
    if not is_authenticated:
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('customers.html', users=users, is_authenticated=is_authenticated)

@app.route('/customers/delete/<int:id>')
def delete_customer(id):
    user = User.query.get(id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash('Customer deleted successfully.', 'success')
        return redirect(url_for('customers'))
    except Exception as e:
        flash('An error occured', str(e), 'danger')
    return render_template('customers.html')

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

@app.route('/user-dashboard/delete/<int:id>')
def delete_user(id):
    user = User.query.get(id)

    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
        return redirect(url_for('user_dashboard'))
    else:
        flash('User not found', 'danger')

    return render_template('dashboard.html')

@app.route('/user-dashboard/create-user', methods=['GET', 'POST'])
@app.route('/customers/create-customers', methods=['GET', 'POST'])
def create_user():
    is_authenticated, current_user = get_authenticated_user()
    # print(current_user)
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username = form.username.data,
            password = hashed_password,
            role = form.role.data,
            created_by = current_user['username'],
            updated_by = None
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully.', 'success')
            if request.path.startswith('/user-dashboard'):
                return(redirect(url_for('user_dashboard')))
            else:
                return redirect(url_for('customers'))
        except Exception as e:
            db.session.rollback()
            flash('An error occured.please try again.', 'danger')
    return render_template('createUser.html', form=form)

@app.route('/user-dashboard/update-user/<int:id>', methods=['GET', 'POST'])
@app.route('/customers/update-customers/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    is_authenticated, current_user = get_authenticated_user()

    if not is_authenticated:
        flash('You must be logged in to update a user.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(id)
    
    form = SignupForm()

    if form.validate_on_submit():
        if form.password.data:  
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password

        user.username = form.username.data 
        user.role = form.role.data
        user.updated_by = current_user['username'] 

        try:
            db.session.commit() 
            flash('User updated successfully.', 'success')
            if request.path.startswith('/user-dashboard'):
                return redirect(url_for('user_dashboard'))
            else:
                return redirect(url_for('customers'))
        except Exception as e:
            db.session.rollback() 
            flash(f'An error occurred: {str(e)}', 'danger')

    form.username.data = user.username
    form.role.data = user.role

    return render_template('updateuser.html', form=form, user=user)

@app.context_processor
def inject_authentication():
    is_authenticated, current_user = get_authenticated_user()
    return dict(is_authenticated=is_authenticated, current_user=current_user)

@app.route('/order', methods=['GET'])
def orders():
    products = Products.query.all()  
    return render_template('orders.html', products=products)


@app.route('/create_order/<int:product_id>', methods=['GET', 'POST'])
def create_order(product_id):
    is_authenticated, current_user = get_authenticated_user()
    product = Products.query.get_or_404(product_id)

    if request.method == 'POST':
        shipping_address = request.form['shipping_address']
        note = request.form.get('note')
        discount = float(request.form.get('discount', 0))
        quantity = int(request.form['quantity'])  

        if product.stock < quantity:
            flash('Not enough stock available!', 'danger')
            return redirect(url_for('order_page'))  

        total_payable = (product.price * quantity) - discount  
        paid_amount = total_payable  
        due_amount = 0 if paid_amount >= total_payable else total_payable - paid_amount

        new_order = Orders(
            shipping_address=shipping_address,
            note=note,
            discount=discount,
            total_payable=total_payable,
            paid_amount=paid_amount,
            due_amount=due_amount,
            status='Pending',
            created_by=current_user['username'],
            updated_by=1 
        )
        db.session.add(new_order)

        product.stock -= quantity
        db.session.commit() 

        flash('Order created successfully!', 'success')
        return redirect(url_for('order_summary', order_id=new_order.id))

    return render_template('create_order.html', product=product)


@app.route('/order_summary/<int:order_id>')
def order_summary(order_id):
    order = Orders.query.get_or_404(order_id)
    return render_template('order_summary.html', order=order)

@app.route('/products')
def products():
    products = Products.query.all()
    return render_template('products.html', products=products)

@app.route('/create-product', methods=['GET', 'POST'])
def create_product():
    is_authenticated, current_user = get_authenticated_user()
    form = AddProductForm()  
    if form.validate_on_submit():
        product = Products(
            name = form.name.data,
            price = form.price.data,
            stock = form.stock.data,
            created_by = current_user['username'],
            updated_by = current_user['username']
        )
        try:
            db.session.add(product)
            db.session.commit()
            flash('Product created successfully.', 'success')
            return redirect(url_for('products'))
        except Exception as e:
            db.session.rollback()
            flash('An error occured.PLease try again', 'danger')
            print(str(e))
    return render_template('createProduct.html', form=form) 

@app.route('/delete-product/<int:id>')
def delete_product(id):
    try:
        product = Products.query.get(id)  
        if product:  
            db.session.delete(product)  
            db.session.commit()  
            flash('Product deleted successfully.', 'success')
        else:
            flash('Product not found.', 'danger')  
    except Exception as e:
        db.session.rollback()  
        flash('Error occurred: {}'.format(str(e)), 'danger')  
    return redirect(url_for('products')) 

@app.route('/update-product/<int:id>', methods=['GET', 'POST'])
def update_product(id):
    product = Products.query.get(id)  
    if not product:
        flash('Product not found.', 'danger')
        return redirect(url_for('products'))

    form = AddProductForm(obj=product) 

    if form.validate_on_submit():
        product.name = form.name.data  
        product.price = form.price.data 
        product.stock = form.stock.data 

        try:
            db.session.commit()  
            flash('Product updated successfully.', 'success')
            return redirect(url_for('products'))
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            flash('Error occurred: {}'.format(str(e)), 'danger')

    return render_template('updateProduct.html', form=form, product=product)

@app.route('/manage-order')
def manage_order():
    is_authenticated, current_user = get_authenticated_user()

    if current_user['role'] == 'admin': 
        orders = Orders.query.all()  
    else:
        orders = Orders.query.filter_by(created_by=current_user['username']).all()
    
    return render_template('order_manager.html', orders=orders)


@app.route('/accept_order/<int:order_id>', methods=['POST'])
def accept_order(order_id):
    order = Orders.query.get_or_404(order_id)
    order.status = 'Accepted'  
    db.session.commit()
    flash('Order accepted successfully!', 'success')
    return redirect(url_for('manage_order'))  

@app.route('/reject_order/<int:order_id>', methods=['POST'])
def reject_order(order_id):
    order = Orders.query.get_or_404(order_id)
    order.status = 'Rejected'
    db.session.commit()
    flash('Order rejected successfully!', 'danger')
    return redirect(url_for('manage_order'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run(debug=True)

