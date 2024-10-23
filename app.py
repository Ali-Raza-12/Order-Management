from flask import Flask, render_template, flash, redirect, url_for, request, g
from models import User, bcrypt, db, Products, Orders
from forms import SignupForm, LoginForm, AddProductForm
from config import Config
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login' 

class AuthUser(UserMixin):
    def __init__(self, user):
        self.id = user.id  
        self.username = user.username
        self.role = user.role

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data, 
            password=hashed_password, 
            role=form.role.data
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            auth_user = AuthUser(user)
            login_user(auth_user)  # Log in the user
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    flash('You have been logged out.', 'info')
    logout_user()  # Log out the user
    return redirect(url_for('home'))

@app.route('/')
def home():
    return render_template('home.html', is_authenticated=current_user.is_authenticated, current_user=current_user)

@app.route('/customers')
@login_required
def customers():
    users = User.query.all()
    return render_template('customers.html', users=users, is_authenticated=current_user.is_authenticated)

@app.route('/customers/delete/<int:id>')
@login_required
def delete_customer(id):
    user = User.query.get(id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('Customer deleted successfully.', 'success')
        return redirect(url_for('customers'))
    except Exception as e:
        flash('An error occurred', str(e), 'danger')
    return render_template('customers.html')

@app.route('/user-dashboard', methods=['GET'])
@login_required
def user_dashboard():
    users = User.query.all()
    return render_template('dashboard.html', current_user=current_user, users=users, is_authenticated=current_user.is_authenticated)

@app.route('/user-dashboard/delete/<int:id>')
@login_required
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
@login_required
def create_user():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            password=hashed_password,
            role=form.role.data,
            created_by=current_user.username,
            updated_by=None
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully.', 'success')
            if request.path.startswith('/user-dashboard'):
                return redirect(url_for('user_dashboard'))
            else:
                return redirect(url_for('customers'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
    return render_template('createUser.html', form=form)

@app.route('/user-dashboard/update-user/<int:id>', methods=['GET', 'POST'])
@app.route('/customers/update-customers/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user(id):
    user = User.query.get_or_404(id)
    form = SignupForm()
    if form.validate_on_submit():
        if form.password.data:  
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
        user.username = form.username.data 
        user.role = form.role.data
        user.updated_by = current_user.username 

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
    return dict(is_authenticated=current_user.is_authenticated, current_user=current_user)

@app.route('/order', methods=['GET'])
@login_required
def orders():
    products = Products.query.all()  
    return render_template('orders.html', products=products)

@app.route('/create_order/<int:product_id>', methods=['GET', 'POST'])
@login_required
def create_order(product_id):
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
            created_by=current_user.username,
            updated_by=1 
        )
        db.session.add(new_order)

        product.stock -= quantity
        db.session.commit() 

        flash('Order created successfully!', 'success')
        return redirect(url_for('order_summary', order_id=new_order.id))

    return render_template('create_order.html', product=product)

@app.route('/order_summary/<int:order_id>')
@login_required
def order_summary(order_id):
    order = Orders.query.get_or_404(order_id)
    return render_template('order_summary.html', order=order)

@app.route('/products')
@login_required
def products():
    products = Products.query.all()
    return render_template('products.html', products=products)

@app.route('/create-product', methods=['GET', 'POST'])
@login_required
def create_product():
    form = AddProductForm()  
    if form.validate_on_submit():
        product = Products(
            name=form.name.data,
            price=form.price.data,
            stock=form.stock.data,
            created_by=current_user.username,
            updated_by=current_user.username
        )
        try:
            db.session.add(product)
            db.session.commit()
            flash('Product created successfully.', 'success')
            return redirect(url_for('products'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again', 'danger')
            print(str(e))
    return render_template('createProduct.html', form=form)

@app.route('/delete-product/<int:id>')
@login_required
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
@login_required
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
@login_required
def manage_order():
    if current_user.role == 'admin': 
        orders = Orders.query.all()  
    else:
        orders = Orders.query.filter_by(created_by=current_user.username).all()
    
    return render_template('order_manager.html', orders=orders)

@app.route('/accept_order/<int:order_id>', methods=['POST'])
@login_required
def accept_order(order_id):
    order = Orders.query.get_or_404(order_id)
    order.status = 'Accepted'  
    db.session.commit()
    flash('Order accepted successfully!', 'success')
    return redirect(url_for('manage_order'))  

@app.route('/reject_order/<int:order_id>', methods=['POST'])
@login_required
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
