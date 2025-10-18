from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

# Initialize extensions
db = SQLAlchemy()

bcrypt = Bcrypt()

# --- Database Models ---

class Customer(db.Model):
    __tablename__ = 'Customer'
    customer_id = db.Column(db.Integer, primary_key=True)
    cust_first_name = db.Column(db.String(50), nullable=False)
    cust_last_name = db.Column(db.String(50), nullable=False)
    dob = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    
    # Relationships with cascade delete for data integrity
    login = db.relationship('Login', backref='customer', uselist=False, cascade="all, delete-orphan")
    details = db.relationship('CustomerDetails', backref='customer', uselist=False, cascade="all, delete-orphan")
    purchases = db.relationship('Purchase', backref='customer', cascade="all, delete-orphan")

class Login(db.Model):
    __tablename__ = 'Login'
    login_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('Customer.customer_id'), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

class CustomerDetails(db.Model):
    __tablename__ = 'CustomerDetails'
    detail_id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(80))
    state = db.Column(db.String(80))
    zip = db.Column(db.String(20))
    phone_number = db.Column(db.String(20))
    email_id = db.Column(db.String(120), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('Customer.customer_id'), nullable=False)

class Category(db.Model):
    __tablename__ = 'Category'
    category_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text)
    
    ebooks = db.relationship('Ebook', backref='category')

class Ebook(db.Model):
    __tablename__ = 'Ebook'
    ebook_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author_name = db.Column(db.String(150), nullable=False)
    genre = db.Column(db.String(80))
    price = db.Column(db.Float, default=0.0)
    file_path = db.Column(db.String(255), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('Category.category_id'))
    
    purchases = db.relationship('Purchase', backref='ebook', cascade="all, delete-orphan")

class Purchase(db.Model):
    __tablename__ = 'Purchase'
    purchase_id = db.Column(db.Integer, primary_key=True)
    ebook_id = db.Column(db.Integer, db.ForeignKey('Ebook.ebook_id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('Customer.customer_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# models.py
class SupportMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(120))
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
