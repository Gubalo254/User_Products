from flask import Flask
from flask_jwt_extended import JWTManager
from models import db
from routes import routes



def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = '7f8d2a9b4c6e1f3d8a2b5c7e9d1f4a6b8c3e2d5f7a9b1c4e6d8f2a3b5c7e9d1'
    
    db.init_app(app)
    JWTManager(app)

    app.register_blueprint(routes)

    with app.app_context():
        db.create_all()

    return app
if __name__ == "__main__":
    app =  create_app()
    
    app.run(debug=True)