from flask import request, jsonify,Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Product
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity, create_access_token

routes = Blueprint("routes", __name__)

@routes.route("/")
def home_page():
    return 'hi my people'


@routes.route("/register", methods =["POST"])
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




@routes.route("/login", methods= ["POST"])
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




@routes.route("/products", methods=["POST"])
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



@routes.route("/users")
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




@routes.route("/getproducts", methods =["GET"])
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



@routes.route("/product/<int:product_id>", methods =["DELETE"])
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


@routes.route("/update/product/<int:product_id>", methods = ["PATCH" ])
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
    data = request.get_json() or {}

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

@routes.route("/remove/users/<int:user_id>", methods =["DELETE"])
@jwt_required()
def remove_user(user_id):
    claims = get_jwt()
    role = claims["role"]
    user = User.query.filter_by(id = user_id).first()
    products = Product.query.filter_by(user_id= user_id).all()
    

    if not user:
        return jsonify({"error": "user not found"})
    
    if role == "user":
       return jsonify({"error": "Access denied!"})
    
    items = []

    for p in products:
        items.append({
            "id": p.id,
            "name":p.name,
            "description":p.description,
            "price":p.price,
            "owner": p.owner.username
        })
   
    user_data = {"id": user.id, "name": user.username, "email": user.email}

    db.session.delete(user)
    db.session.commit()


    return jsonify({"msg":"you removed a user","user":{"id":user_data["id"], "username":user_data["name"], "email":user_data["email"]}, "mssg": f"{user_data['name']}'s products cleared from the db as well", "products": items })
    

@routes.route("/update/user/<int:user_id>", methods =["PATCH"])
@jwt_required()
def update_user(user_id):
    current_user = get_jwt_identity()
    current_user_id = int(current_user)
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({"error": "no such user"})
    
    if current_user_id != user.id:
        return jsonify({"error": "you are not allowed to update this users details"})
    
    
    user_data = request.get_json()
    if "username" in user_data:
            user.username = user_data["username"]
    if "email" in user_data:
            user.email = user_data["email"]
    if "password" in user_data:
            password = user_data["password"]
            password_hashed = generate_password_hash(password)
            user.hash_password = password_hashed

    db.session.commit()
    return jsonify({"msg": "user's details updated successfully","user": {
            "id": user.id,
            "name": user.username,
            "email": user.email}
    }), 200

