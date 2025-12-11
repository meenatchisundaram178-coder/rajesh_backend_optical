from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import bcrypt
import os # NEW: Required for reading environment variables
from datetime import timedelta

# --- CONFIGURATION ---
app = Flask(__name__)

# !!! CRITICAL FOR SECURITY AND DEPLOYMENT !!!
# Read SECRET_KEY from Render environment variable. 
# The default is ONLY for local testing if the variable isn't set.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'FALLBACK_INSECURE_DEV_KEY_CHANGE_ME_NOW')

# Database configuration (Use a proper DATABASE_URL from Render for production)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///rajesh_opticals.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set the session cookie to expire after 100 days for permanent login
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=100)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=100)

# --- CORS FIX (Allows your local HTML/JS to talk to the Render API) ---
# List ALL domains/origins that are allowed to talk to your API.
ALLOWED_ORIGINS = [
    "http://localhost",               # For testing with local servers
    "http://127.0.0.1",               # Another common local address
    "http://localhost:5500",          # Common port for VS Code Live Server
    "file://",                        # Allows requests from local HTML files (less secure, but fixes your current issue)
    "https://rajesh-backend-optical-1.onrender.com", # Your own backend URL (Render)
    "https://your-future-frontend-domain.com", # Replace this with your final frontend URL
]

# Note: supports_credentials=True is essential for sending cookies (sessions/login)
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS) 
# --- END CORS FIX ---


db = SQLAlchemy(app)

# --- FLASK-LOGIN SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    """Required by Flask-Login to load a user from the ID stored in the session/cookie."""
    return User.query.get(int(user_id))

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Staff')
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        # NOTE: bcrypt.checkpw automatically handles the salt
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)

    def __repr__(self):
        return f'<User {self.username}>'


# --- ROUTES ---

# SIGNUP ROUTE
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not all([data.get('fullname'), data.get('phone'), data.get('email'), username, password]):
        return jsonify({'ok': False, 'msg': 'All fields are required!'}), 400

    # Check for existing user (username or phone)
    if User.query.filter((User.username == username) | (User.phone == data.get('phone'))).first():
        return jsonify({'ok': False, 'msg': 'Username or Phone already exists.'}), 409

    new_user = User(
        fullname=data.get('fullname'),
        phone=data.get('phone'),
        email=data.get('email'),
        username=username,
        role=data.get('role', 'Staff')
    )
    new_user.set_password(password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        # Optional: Log the user in immediately after signup
        login_user(new_user, remember=True) 
        session['role'] = new_user.role
        return jsonify({'ok': True, 'msg': 'Signup successful! Redirecting to Home.'}), 201
    except Exception as e:
        db.session.rollback()
        # Log the full error to the server console for debugging
        print(f"Signup error: {e}") 
        return jsonify({'ok': False, 'msg': f'Internal Server Error during signup.'}), 500


# LOGIN ROUTE (Uses remember=True for permanent login)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username_or_phone = data.get('username')
    password = data.get('password')
    
    if not all([username_or_phone, password]):
        return jsonify({'ok': False, 'msg': 'Username and Password are required!'}), 400
    
    # Try to find user by username or phone
    user = User.query.filter((User.username == username_or_phone) | (User.phone == username_or_phone)).first()

    if user and user.check_password(password):
        # PERMANENT LOGIN FIX: 'remember=True' tells Flask-Login to set the long-lasting cookie.
        login_user(user, remember=True) 
        session['role'] = user.role # Store role in session for easy access
        
        return jsonify({'ok': True, 'msg': f'Login successful! Role: {user.role}'}), 200
    else:
        return jsonify({'ok': False, 'msg': 'Invalid Username or Password'}), 401


# LOGOUT ROUTE
@app.route('/logout')
@login_required # Ensures only an authenticated user can perform this action
def logout():
    # Flask-Login removes the session and the long-term 'remember me' cookie.
    logout_user() 
    return jsonify({'ok': True, 'msg': 'Logged out successfully'}), 200

# PROTECTED ROUTE Example
@app.route('/check_auth')
def check_auth():
    """Checks if the user is currently logged in (either via short session or long-term cookie)."""
    if current_user.is_authenticated:
        return jsonify({'ok': True, 'user_id': current_user.id, 'username': current_user.username, 'role': session.get('role', 'Unknown')}), 200
    else:
        return jsonify({'ok': False, 'msg': 'Not authenticated'}), 401

# --- APP STARTUP ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates tables if they don't exist
    app.run(debug=True)