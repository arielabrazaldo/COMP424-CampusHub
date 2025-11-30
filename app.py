# app.py

from flask import Flask, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy

# Initialize db object globally but without the app yet
db = SQLAlchemy() 

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

    # IMPORT ROUTES AND FORMS HERE TO AVOID CIRCULAR IMPORTS
    from forms import RegistrationForm 
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
            flash(f'Account created for {form.username.data}!', 'success')
            return redirect(url_for('hello_world')) 
        return render_template('register.html', title='Register', form=form)

    return app

# If running directly, run the create_app function
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)