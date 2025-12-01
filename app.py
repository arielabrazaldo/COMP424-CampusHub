# app.py

from flask import Flask, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, logout_user, login_required

# Initialize db object globally but without the app yet
db = SQLAlchemy() 

# Initialize Bcrypt globally
bcrypt = Bcrypt()

# Initialize LoginManager globally
login_manager = LoginManager()

# Function to create and configure the app
def create_app():
    app = Flask(__name__)

    # Configuration for Flask-WTF Secret Key
    app.config['SECRET_KEY'] = 'your_super_secret_key_change_me' 

    # Configuration for SQLAlchemy
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

    # Initialize the database with the app
    db.init_app(app) 

    # Initialize Bcrypt with the app
    bcrypt.init_app(app)

    # Initialize LoginManager with the app
    login_manager.init_app(app)

    # Function to reload the user from the user ID stored in the session
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Configure the view function that handles logins
    login_manager.login_view = 'login'

    # Configure the message category for flashes (Bootstrap class)
    login_manager.login_message_category = 'info'

    # IMPORT ROUTES AND FORMS HERE TO AVOID CIRCULAR IMPORTS
    from forms import RegistrationForm, LoginForm
    from models import User

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

    return app

# If running directly, run the create_app function
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)