# app.py

import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, render_template, url_for, flash, redirect, jsonify, request, session
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

    # --- Secure Session & Cookie Configuration -------------------------------
    # HttpOnly (Not accessible to JavaScript)
    app.config['SESSION_COOKIE_HTTPONLY'] = True

    # Secure (Only sent over HTTPS)
    # toggle "True" to disable cookies, session and CSRF tokens on HTTP
    app.config['SESSION_COOKIE_SECURE'] = False

    # SameSite=Lax (Protects against CSRF)
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # short-lived (30 minutes)
    # Max-Age is in seconds (1800 seconds = 30 minutes)
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800
    # -------------------------------------------------------------------------

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

    # ------------------------------ Routes -----------------------------------------------------
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
                # session object
                from flask import session
                session.permanent = True # enforces 30-minute session expiry from configuration

                from flask_login import login_user # Import here to avoid conflict
                login_user(user, remember=form.remember.data)
                flash('Login successful!', 'success')
                return redirect(url_for('hello_world')) 
            else:
                flash('Login Unsuccessful. Please check email and password.', 'danger')
        return render_template('login.html', title='Login', form=form)
    
    @app.route("/notes")
    @login_required
    def notes_page():
        return render_template("notes.html")

    # --------------------- Notes API Routes -------------------------------------------------------
    @app.route("/api/notes", methods=['GET', 'POST'])
    @login_required
    def api_notes():
        from models import Note # Ensure Note is imported
        from flask_login import current_user
        
        # GET /api/notes: View all notes for the authenticated user
        if request.method == 'GET':
            notes = Note.query.filter_by(user_id=current_user.id).all()
            
            # Convert notes to a list of dictionaries for JSON response
            notes_data = []
            for note in notes:
                notes_data.append({
                    'id': note.id,
                    'title': note.title,
                    'content': note.content,
                    'date_posted': note.date_posted.isoformat()
                })
            return jsonify(notes_data)

        # POST /api/notes: Create a new note
        elif request.method == 'POST':
            # Must have JSON data
            if not request.is_json:
                return jsonify({"error": "Missing JSON in request"}), 400
                
            data = request.get_json()
            if not data or 'title' not in data or 'content' not in data:
                return jsonify({"error": "Missing title or content field"}), 400

            new_note = Note(
                title=data['title'],
                content=data['content'],
                user_id=current_user.id # Links the note to the current user!
            )
            db.session.add(new_note)
            db.session.commit()
            
            return jsonify({
                "message": "Note created successfully", 
                "id": new_note.id
            }), 201

    @app.route("/api/notes/<int:note_id>", methods=['PUT', 'DELETE'])
    @login_required
    def api_note_detail(note_id):
        from models import Note
        from flask_login import current_user
        
        note = Note.query.get_or_404(note_id)

        # --- AUTHORIZATION CHECK: MUST BE THE OWNER ---
        if note.user_id != current_user.id:
            return jsonify({"error": "Unauthorized access. You do not own this note."}), 403
        # --- END AUTHORIZATION CHECK ---

        # PUT /api/notes/{id}: Update a note
        if request.method == 'PUT':
            if not request.is_json:
                return jsonify({"error": "Missing JSON in request"}), 400
                
            data = request.get_json()
            
            if 'title' in data:
                note.title = data['title']
            if 'content' in data:
                note.content = data['content']
                
            db.session.commit()
            
            return jsonify({"message": f"Note {note_id} updated successfully"})

        # DELETE /api/notes/{id}: Delete a note
        elif request.method == 'DELETE':
            db.session.delete(note)
            db.session.commit()
            
            return jsonify({"message": f"Note {note_id} deleted successfully"})
        

    # --------------- Google OAuth Route ----------------------------------------------------------
    @app.route("/logout")
    def logout():
        # Clears the session cookie, effectively logging the user out
        logout_user() 
        session.clear()
        response = redirect(url_for('hello_world'))
        response.delete_cookie(app.config['SESSION_COOKIE_NAME'])
        flash("You have been logged out.", 'info')
        return response
    
    @app.route("/timeout_logout")
    @login_required
    def timeout_logout():
        """Logs out the user and shows a message specific to inactivity."""
        # Note: 'logout_user' and 'flash' should be imported globally or inside the function if needed
        from flask_login import logout_user # Ensure this is imported if not global
        logout_user() 
        flash("You were logged out due to 30 minutes of inactivity.", 'warning')
        return redirect(url_for('login'))
    
    @app.route('/login/google')
    def login_google():
        """Initiates the Google OAuth login flow."""
        google = oauth.create_client('google')
        # Use the named redirect endpoint 'authorize_google'
        redirect_uri = url_for('authorize_google', _external=True) 
        return google.authorize_redirect(redirect_uri)

    @app.route('/google/auth')
    def authorize_google():
        # ---------------------- Token processing and user creation -------------------------------
        """Handles the callback from Google, authenticates the user, and logs them in."""
        google = oauth.create_client('google')
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json() # Fetch user data (email, name)

        # --- Database and Login Logic --------------
        user = User.query.filter_by(email=user_info['email']).first()
    
        if user is None:
            # Create a new user record for the OAuth user
            user = User(username=user_info['name'],
                        email=user_info['email'],
                        password='') # Password is a placeholder for OAuth users
            db.session.add(user)
            db.session.commit()
        # -------------------------------------------
    
        # Log the user into the Flask session
        from flask_login import login_user
        from flask import session

        # enforce 30-minute session expiry from configuration
        session.permanent = True

        login_user(user)
    
        flash(f'Successfully logged in with Google as {user.username}!', 'success')
        return redirect(url_for('hello_world'))
        # -------------------------------------------------------------------------------------------

    # ---------------------- CSRF Token Route ---------------------------------------
    @app.route("/csrf", methods=["GET"])
    @login_required
    def get_csrf_token():
        """
        Issues a CSRF token tied to the current session.

        Frontend should call GET /csrf after login and then send this token
        in the 'x-csrf-token' header for all POST/PUT/DELETE requests to /api/*.
        """
        token = session.get("csrf_token")
        if not token:
            token = token_urlsafe(32)
            session["csrf_token"] = token

        return jsonify({"csrf_token": token})
    
    # ---------------------- CSRF Protection for API Writes ------------------------
    @app.before_request
    def csrf_protect_api():
        """
        Enforce CSRF token on all modifying API requests.

        - Only applies to POST/PUT/DELETE
        - Only for routes under /api/
        - Token must be sent in 'x-csrf-token' header
        - Token must match the one stored in the session by /csrf
        """
        if request.method in ("POST", "PUT", "DELETE"):
            if request.path.startswith("/api/"):
                header_token = request.headers.get("x-csrf-token")
                session_token = session.get("csrf_token")

                if not session_token or not header_token or header_token != session_token:
                    return jsonify({"error": "Invalid CSRF token"}), 403

    return app

# If running directly, run the create_app function
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)