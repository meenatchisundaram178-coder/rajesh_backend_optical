# app.py

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import HTTPException # <-- Import this
import bcrypt
import os

# --- Configuration ---
app = Flask(__name__)

# 1. Use environment variable for the SECRET_KEY (MANDATORY for security)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_dev_key_if_not_set')

# 2. Database Configuration for Production (Render)
# Recommended to use PostgreSQL for Render deployment, but sticking to SQLite for initial setup.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup CORS to allow your frontend to access the API
CORS(app, supports_credentials=True, origins=["https://rajesh-backend-72q8.onrender.com", "http://localhost:5500", "YOUR_FRONTEND_DOMAIN_HERE"])

db = SQLAlchemy(app)

# --- GLOBAL ERROR HANDLER (Prevents the '<!doctype' error) ---
@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    return jsonify({
        'ok': False,
        'msg': e.description or 'A server error occurred.',
        'code': e.code
    }), e.code

# --- Database Model (User Schema) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    role = db.Column(db.String(10), default='Staff')

# Create the database tables
with app.app_context():
    db.create_all()

# --- 1. SIGNUP Route (/signup) ---
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        fullname = data.get('fullname')
        phone = data.get('phone')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'Staff')

        if not all([fullname, phone, email, username, password]):
            return jsonify({'ok': False, 'msg': 'All fields are required!'}), 400

        if User.query.filter_by(username=username).first() or User.query.filter_by(phone=phone).first():
            return jsonify({'ok': False, 'msg': 'Username or Phone already exists.'}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(fullname=fullname, phone=phone, email=email, username=username, password_hash=hashed_password, role=role)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Set session only after successful signup
        session['user_id'] = new_user.id 
        
        return jsonify({'ok': True, 'msg': 'Signup successful! Redirecting to Home.'}), 201
    except Exception as e:
        db.session.rollback()
        # Handle unspecific server errors, ensuring JSON is returned
        return jsonify({'ok': False, 'msg': f'Internal Server Error during signup: {str(e)}'}), 500


# --- 2. LOGIN Route (/login) ---
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username_or_phone = data.get('username') 
        password = data.get('password')

        if not all([username_or_phone, password]):
            return jsonify({'ok': False, 'msg': 'Username and Password are required!'}), 400

        # Find user by username OR phone number
        user = User.query.filter((User.username == username_or_phone) | (User.phone == username_or_phone)).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            # Successful Login: Set session cookie
            session['user_id'] = user.id
            session['role'] = user.role
            return jsonify({'ok': True, 'msg': f'Login successful! Role: {user.role}'}), 200
        else:
            return jsonify({'ok': False, 'msg': 'Invalid Username or Password'}), 401
    except Exception as e:
        return jsonify({'ok': False, 'msg': f'Internal Server Error during login: {str(e)}'}), 500

# --- 3. LOGOUT Route ---
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return jsonify({'ok': True, 'msg': 'Logged out successfully.'}), 200

# --- 4. Protected Route Example (for checking session status) ---
@app.route('/check_auth')
def check_auth():
    if 'user_id' in session:
        return jsonify({'ok': True, 'user_id': session['user_id'], 'role': session['role']}), 200
    else:
        # User not logged in
        return jsonify({'ok': False, 'msg': 'Not authenticated'}), 401