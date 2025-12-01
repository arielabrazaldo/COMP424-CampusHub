# app.py

import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, logout_user, login_required
from authlib.integrations.flask_client import OAuth

# Initialize db object globally but without the app yet
db = SQLAlchemy() 

# Initialize Bcrypt globally
bcrypt = Bcrypt()

# Initialize LoginManager globally
login_manager = LoginManager()

# Initialize OAuth globally
oauth = OAuth()

# Function to create and configure the app
def create_app():

    # Import the globally defined objects into the function's scope
    global db, bcrypt, login_manager, oauth

    app = Flask(__name__)

    # --- Google OAuth Configuration -----------------------------------------
    app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

    # Configuration for Flask-WTF Secret Key
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
    # ------------------------------------------------------------------------

    # Configuration for SQLAlchemy
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

    # Initialize the database with the app
    db.init_app(app) 

    # Initialize Bcrypt with the app
    bcrypt.init_app(app)

    # Initialize LoginManager with the app
    login_manager.init_app(app)

    # Initialize OAuth with the app
    oauth.init_app(app)

    # Register the google remote app 
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        access_token_url='https://oauth2.googleapis.com/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'openid email profile'}, # Request user email and profile
    )

    # Configure the view function that handles logins
    login_manager.login_view = 'login'

    # Configure the message category for flashes (Bootstrap class)
    login_manager.login_message_category = 'info'

    # IMPORT ROUTES AND FORMS HERE TO AVOID CIRCULAR IMPORTS
    from forms import RegistrationForm, LoginForm
    from models import User

    # Function to reload the user from the user ID stored in the session
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- Routes ---
    
    @app.route("/")
    @app.route("/home")
    def hello_world():
        # Flash messages are defined here to ensure they are available
        return render_template('index.html') 

    @app.route("/register", methods=['GET', 'POST'])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            # Hashing and saving user logic will go here
            # 1. hash the password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            # 2. create a new user object
            user = User(username=form.username.data,
                        email=form.email.data,
                        password=hashed_password)
            
            # 3. add the user to the database session and commit
            db.session.add(user)
            db.session.commit()

            flash(f'Account created for {form.username.data}!', 'success')
            return redirect(url_for('hello_world')) 
        return render_template('register.html', title='Register', form=form)
    
    @app.route("/login", methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            # Find the user by email
            user = User.query.filter_by(email=form.email.data).first()

            # Check if user exists AND password is correct
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                from flask_login import login_user # Import here to avoid conflict
                login_user(user, remember=form.remember.data)
                flash('Login successful!', 'success')
                return redirect(url_for('hello_world')) 
            else:
                flash('Login Unsuccessful. Please check email and password.', 'danger')
        return render_template('login.html', title='Login', form=form)
    
    @app.route("/logout")
    def logout():
        # Clears the session cookie, effectively logging the user out
        logout_user() 
        flash("You have been logged out.", 'info')
        return redirect(url_for('hello_world'))
    
    @app.route('/login/google')
    def login_google():
        """Initiates the Google OAuth login flow."""
        google = oauth.create_client('google')
        # Use the named redirect endpoint 'authorize_google'
        redirect_uri = url_for('authorize_google', _external=True) 
        return google.authorize_redirect(redirect_uri)

    @app.route('/google/auth')
    def authorize_google():
        """Handles the callback from Google, authenticates the user, and logs them in."""
        google = oauth.create_client('google')
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json() # Fetch user data (email, name)

        # --- Database and Login Logic ---
        user = User.query.filter_by(email=user_info['email']).first()
    
        if user is None:
            # Create a new user record for the OAuth user
            user = User(username=user_info['name'],
                        email=user_info['email'],
                        password='') # Password is a placeholder for OAuth users
            db.session.add(user)
            db.session.commit()
    
        # Log the user into the Flask session
        from flask_login import login_user
        login_user(user)
    
        flash(f'Successfully logged in with Google as {user.username}!', 'success')
        return redirect(url_for('hello_world'))

    return app

# If running directly, run the create_app function
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)