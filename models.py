# models.py

from app import db # Import the database object (db) from the main application file
from flask_login import UserMixin


# Model is a Python class that will represent table in database
# Create the user model/table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # string password just to get started, will implement hashing later!
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"