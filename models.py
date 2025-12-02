# models.py

from datetime import datetime
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
    
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Foreign Key linking the note to a User
    # 'user.id' refers to the table name ('user') and column name ('id')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

    def __repr__(self):
        return f"Note('{self.title}', '{self.date_posted}')"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Foreign Key linking the post to a User
    # 'user.id' refers to the table name ('user') and column name ('id')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"