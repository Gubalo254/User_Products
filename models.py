from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


BLOCKLIST = set()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) 
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default="user") 
    products = db.relationship("Product", backref="owner", lazy=True, cascade = "all, delete-orphan") 




class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    

    def __repr__(self):
        return f"<User {self.username}>"
