from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required,get_jwt, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = '7f8d2a9b4c6e1f3d8a2b5c7e9d1f4a6b8c3e2d5f7a9b1c4e6d8f2a3b5c7e9d1'
jwt = JWTManager(app)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) 
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default="user") 
    products = db.relationship("Product", backref="owner", lazy=True) 




class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    

    def __repr__(self):
        return f"<User {self.username}>"

@app.route("/")
def home_page():
    return 'hi my people'


@app.route("/register", methods =["POST"])
def register_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    hashed_password = generate_password_hash(password)


    if not username or not email:
        return jsonify ({"error":"username and email are required"}), 400
    
    if  User.query.filter(User.email==email).first():
        return jsonify ({"error": "user already exists"}), 400
    
    if not password:
        return jsonify({"error":"password required!"})
    
    new_user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify ({"message": "user created successfully", "user": {"id":new_user.id, "username":new_user.username, "email":new_user.email}}), 201




@app.route("/login", methods= ["POST"])
def login_user():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash( user.password_hash, password):
        return jsonify({"error": "invalid email or password"})
    

    access_token = create_access_token(
    identity=str(user.id), 
    additional_claims={"role": user.role}
)
    return jsonify(access_token=access_token), 200



@app.route("/users")
@jwt_required()
def users_registered():
    claims= get_jwt()

    if claims["role"] != "admin":
        return jsonify({"error": "Admins only!"}), 403
    

    users = User.query.all()
    results = []
    for user in users:
        results.append({
            "id":user.id,
            "username":user.username,
            "email": user.email
                            })
    return jsonify({"users": results})




@app.route("/products", methods=["POST"])
@jwt_required()
def product_create():

    user_id = get_jwt_identity()

    data = request.get_json()
    name = data.get("name")
    description = data.get("description")
    price = data.get("price")
    
    if not name or not description:
        return jsonify({"error": "name and description required"}), 400
    
    if not price:
        return jsonify({"error": "price required"}), 400
    
    try:
        price = float(price)
    except ValueError:
        return jsonify({"error": "price must be a number"}), 400

    new_product = Product(name=name, description=description, price=price, user_id=user_id)
    db.session.add(new_product)
    db.session.commit()


    return jsonify({"message": "product created successfully"}), 201


@app.route("/getproducts", methods =["GET"])
@jwt_required()
def get_products():
    claims= get_jwt()
    current_user_id = get_jwt_identity()
    role = claims.get("role")

    if role == "user":
        products = Product.query.filter_by(user_id= current_user_id).all()

    else:
        products = Product.query.all()



    item = []

    for p in products:
        item.append({
            "id": p.id,
            "name":p.name,
            "description":p.description,
            "price":p.price,
            "owner": p.owner.username
        })
    if not item:
        return jsonify({"msg": "there are no products here yet"})
    return jsonify({"products":item})   



@app.route("/product/<int:product_id>", methods =["DELETE"])
@jwt_required()
def delete_product(product_id):
    current_user = get_jwt_identity()
    claims = get_jwt()
    role = claims.get('role')
    product = Product.query.filter_by(id = product_id).first()

    if not product:
        return jsonify({"error": "product not found"}), 404
   
    if role == "user" and product.user_id != int(current_user):
        return jsonify({"error": "you are not allowed to delete this product"}), 403
    db.session.delete(product)
    db.session.commit()
    return jsonify({"msg":f"product {product.name} deleted succesfully"}), 200


@app.route("/update/product/<int:product_id>", methods = ["PATCH" ])
@jwt_required()
def update_product(product_id):
    claims = get_jwt()
    current_user = get_jwt_identity()
    role = claims["role"]

    product = Product.query.filter_by(id = product_id).first()
    
    if not product:
        return jsonify({"error": "product not found"}), 404
    if role == "user" and product.user_id != int(current_user):
        return jsonify({"error": "you are not allowed to make an update of this product"}), 403
    data = request.get_json()

    if "name" in data:
        product.name = data["name"]
    if "description" in data:
        product.description = data["description"]
    if "price" in data:
       price = data["price"]
       if price is not None:
            try:
                product.price = float(price)
            except ValueError:
                return jsonify({"error": "price must be a number"}), 400
    

    db.session.commit()

    return jsonify({
        "msg": f"Product {product.name} updated successfully",
        "product": {
            "id": product.id,
            "name": product.name,
            "description": product.description,
            "price": product.price,
            "owner": product.owner.username
        }
    }), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)