from flask import Flask
from flask_jwt_extended import JWTManager
from models import db, BLOCKLIST
from routes import routes
import os
from dotenv import load_dotenv
from datetime import timedelta


jwt = JWTManager()

load_dotenv()



def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes =int(os.getenv("JWT_EXPIRES_MINUTES")))


    db.init_app(app)
    jwt.init_app(app)
                                        


    

    app.register_blueprint(routes)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
       jti = jwt_payload["jti"]
       return jti in BLOCKLIST

    with app.app_context():
        db.create_all()

    return app
if __name__ == "__main__":
    app =  create_app()
    
    app.run(debug=True)