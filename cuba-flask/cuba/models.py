from .import db
import datetime
from flask_login import UserMixin


class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique=True,nullable=False)
    email = db.Column(db.String(120), unique=True,nullable=False)
    password = db.Column(db.String(600), nullable=False)    
    isAdmin = db.Column(db.Boolean,default=False)
    
    def __repr__(self):
        return f"User('{self.username}','{self.email}')"
    

class Todo(db.Model):
    id = db.Column(db.Integer,primary_key = True) 
    description = db.Column(db.String(500),unique=True,nullable=False)
    completed = db.Column(db.Boolean, default=False)
    timeStamp = db.Column(db.DateTime,default=datetime.datetime.utcnow)
