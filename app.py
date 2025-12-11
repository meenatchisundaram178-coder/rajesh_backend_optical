from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import bcrypt
from datetime import timedelta
# NOTE: You must also import 'os' and 'secrets' if you are using 'os.environ' for the secret key

# --- CONFIGURATION ---
app = Flask(__name__)
CORS(app, supports_credentials=True)

# !!! IMPORTANT: Fetch from environment variables on Render !!!
app.config['SECRET_KEY'] = 'YOUR_SUPER_SECRET_KEY_HERE_CHANGE_ME_NOW'  # Replace with os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rajesh_opticals.db' # Replace with os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set the session cookie to expire after 100 days (or more)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=100) # For persistent login
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=100) # For standard session

db = SQLAlchemy(app)

# --- FLASK-LOGIN SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Define the view Flask-Login redirects to

# This function tells Flask-Login how to load a user object from the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DATABASE MODELS ---
# UserMixin provides methods like is_authenticated, is_active, get_id() needed by Flask-Login
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

# (You can add your other models like Customer, Order, etc. here)


# --- ROUTES ---

# SIGNUP ROUTE
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # ... (other data: fullname, phone, email, role)

    if not all([username, password]):
        return jsonify({'ok': False, 'msg': 'Missing required fields'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'ok': False, 'msg': 'Username already exists'}), 409

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
        return jsonify({'ok': True, 'msg': 'User registered successfully!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'msg': f'Database error: {str(e)}'}), 500


# LOGIN ROUTE (The change for permanent login is here)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # The frontend only sends username/phone and password, but the backend must check both fields.
    
    # Try to find user by username or phone
    user = User.query.filter((User.username == username) | (User.phone == username)).first()

    if user and user.check_password(password):
        # The magic line for PERMANENT login!
        # Flask-Login sets a special, long-lasting cookie (max_age is set by REMEMBER_COOKIE_DURATION)
        login_user(user, remember=True) 
        
        # You can still use the standard session to store extra info if needed
        session['role'] = user.role 
        
        return jsonify({'ok': True, 'msg': f'Login successful! Role: {user.role}'}), 200
    else:
        return jsonify({'ok': False, 'msg': 'Invalid credentials'}), 401


# LOGOUT ROUTE
@app.route('/logout')
@login_required # Ensure only logged-in users can logout
def logout():
    # Flask-Login removes the session and the long-term 'remember me' cookie.
    logout_user() 
    return jsonify({'ok': True, 'msg': 'Logged out successfully'}), 200

# PROTECTED ROUTE Example
@app.route('/dashboard_data')
@login_required # This is how you protect any route!
def dashboard_data():
    return jsonify({
        'user': current_user.username,
        'role': current_user.role,
        'data': 'Your secure dashboard data here.'
    }), 200

# --- APP STARTUP ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)