from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

# Create the Flask application instance
app = Flask(__name__)

# This will tell Flask-SQLAlchemy where to store the database file.
# 'sqlite:///site.db' means a file named 'site.db' will be created 
# in the root of your project directory.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False # Silcence a deprecation warning
db = SQLAlchemy(app) # creates the database object

# Model is a Python class that will represent table in database
# Create the user model/table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # string password just to get started, will implement hashing later!
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

# Define the route for the home page ('/')
@app.route('/')
def hello_world():
    return render_template('index.html')

# This runs the application
if __name__ == '__main__':
    app.run(debug=True)