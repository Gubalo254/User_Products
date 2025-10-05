from flask import Flask
from flask_jwt_extended import JWTManager
from models import db
from routes import routes
import os
from dotenv import load_dotenv


load_dotenv()



def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
    
    db.init_app(app)
    JWTManager(app)

    app.register_blueprint(routes)

    with app.app_context():
        db.create_all()

    return app
if __name__ == "__main__":
    app =  create_app()
    
    app.run(debug=True)