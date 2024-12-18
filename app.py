from flask import Blueprint, request, jsonify, session,Flask
from flask_jwt_extended import JWTManager
from models import db,User,Course,Course_Buy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_migrate import Migrate
from flask_jwt_extended import jwt_required, get_jwt_identity,verify_jwt_in_request
from dotenv import load_dotenv
import os
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
    get_jwt
)

load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['JWT_SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SECRET_KEY'] = os.getenv("JWT_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 90
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 7 * 24 * 60 * 60  
db.init_app(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# To store revoked tokens (for logout functionality)
revoked_tokens = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload["jti"] in revoked_tokens


# For Sign Up or Register the User.
@app.route("/signup", methods = ['POST'])
def signup():
    try:
        data = request.get_json()

        # to check all fields are required
        if not all(k in data for k in ['name', 'email', 'password']):
            return jsonify({'error': 'Name, email, and password are required'}), 400
        
        name, email, password,address = data['name'], data['email'], data['password'], data['address']

        # Check if email is already registered
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Default Adin Is False
        is_admin = False
        
        # To Check if we are creating new admin then only admin can add new admin.
        if "is_admin" in data and verify_jwt_in_request():
            if User.query.filter_by(id=get_jwt_identity()).first().is_admin:
                is_admin = True
            else:
                return jsonify({"message" : "Only Admin Can Create New Admin"}), 401

        #To Convert Password in Hassed Form and add user
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password, address=address,is_admin = is_admin)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully', 'user_id': new_user.id}), 201
    except BaseException as Error:
        return jsonify({"Error" : f"{Error}"})

# tO Sign in user.
@app.route("/signin",methods = ["POST"])
def signin():
    try:
        data = request.get_json()

        #To Filter by email  or fetch user password
        email,password = data['email'],data['password']
        user = User.query.filter_by(email=email).first()

        #To check is user is in database or password is correct
        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        #To Create JWT token
        # token = create_access_token(identity=str(user.id))
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        # session["jwt"] = token

        # return jsonify({'message': 'Login successful', 'token': token}), 200
        response = jsonify({'message': 'Login successful',"Token" : access_token})
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)
        return response, 200
    except BaseException as Error:
        return jsonify({"Error" : f"{Error}"})


# Refresh Token Endpoint
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        response = jsonify({"message": "Token refreshed","Access Token" : access_token})
        set_access_cookies(response, access_token)
        return response, 200
    except Exception as e:
        return jsonify({"Error": str(e)}), 500
    
# User Logout
@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    try:
        jti = get_jwt()["jti"]
        revoked_tokens.add(jti)
        response = jsonify({"message": "Logout successful"})
        unset_jwt_cookies(response)
        return response, 200
    except Exception as e:
        return jsonify({"Error": str(e)}), 500


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome, user {current_user}!"}), 200


# Python Decoreter To check To User is Admin.
def is_admin(func):
    def inner(*args , **kwargs):
        user_id = get_jwt_identity()
        is_admin_user = User.query.filter_by(id = user_id).first()
        
        if is_admin_user.is_admin:
            return func(*args,**kwargs)
        return jsonify({"message" : "Only Admin Can Add The Course"})

        return func(*args,**kwargs)
    return inner


#To add new courses only admin can add
@app.route("/add_course",methods = ['POST'])
@jwt_required()
@is_admin
def add_course():
    try:
        data = request.get_json()
        required_fields = ['name', 'description', 'price']

        # To Check All Fields Are Required if yes then return the error
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"message": "All Field All Required"}),400
        

        name, price,description = data['name'],data['price'],data["description"]

        #To Convert price in float or check price is nagitive if yes then return error
        try:
            price = float(price)

            if price<0:
                return jsonify({"message" : "Price Must Be Positive"}), 400
        except BaseException as Error:
            return jsonify({"message" : f"Error : {Error}"})
        
        # To add new courses new DB
        new_course =  Course(name=name, description=description, price=price,)
        db.session.add(new_course)
        db.session.commit()

        return jsonify({"message" : "Course Add SuccessFully", "course_id" : new_course.id })
    except BaseException as Error:
        return jsonify({
            "Error" : f"{Error}"
        })
    

# To get all courses in DB only admin can show this
@app.route("/get_course",methods = ["GET"])
@jwt_required()
def get_course():
    try:
        # To check Login user is admin or not
        user_is_admin = User.query.filter_by(id = get_jwt_identity()).first().is_admin
        if not user_is_admin:
            return jsonify({"message": "Only Admin Can Access"})

        # To get all courses in DB if not COurses in DB thrn Return Error
        data = Course.query.all()
        if not data:
            return jsonify({"message" : "Course Not Found"}),404
        
        return jsonify({'course' : [{
            'Course_Id' : course.id,
            "Course_Name" : course.name, 
            "Course_Description" : course.description,
            "Course Price" : course.price}  
            for course in data
        ]})

    except BaseException as Error:
        return jsonify({
            "Error" : f"{Error}"
        })

# To delete course from DB only admin can delete
@app.route("/delete_course", methods= ["DELETE"])
@jwt_required()
def delete_course():
    try:
        if not  User.query.filter_by(id = get_jwt_identity()).first().is_admin:
            return jsonify({"Error" : "Only Admin Can Delete The Course"}),401
        
        #To fetch data from responce and show error if any field is missing
        data = request.get_json()
        if not data:
            return jsonify({"Error": "COurse id Is Requeired To Delete The Course"}),400
        course = Course.query.filter_by(id = data["course_id"]).first()

        # To check is delete course in db or not
        if not course:
            return jsonify({"Error" : "Course Is Not Found for This Id"}), 404
        
        # To delete the course
        db.session.delete(course)
        db.session.commit()

        return jsonify({"Message" : "Course Delete SuccessFully"})
    except BaseException as Error:
        return jsonify({
            "Error" : f"{Error}"
        })

@app.route("/update_course/<int:course_id>", methods = ["PUT"])
@jwt_required()
def update_course(course_id):
    try:
        if not User.query.filter_by(id = get_jwt_identity()).first().is_admin:
            return jsonify({"Error" : "Only Admin Can Updated The Course Information"}),401

        course = Course.query.filter_by(id = course_id).first()

        if not course:
            return jsonify({"Error" : "Course Not Found"}),404
        
        data = request.get_json()
        print(data)
        if "course_name" in data:
            course.name = data["course_name"]
            print(course.name)
        if "price" in data:
            course.price = data["price"]
        if "description" in data:
            course.description = data["description"]

        db.session.commit()

        return jsonify({"Message" : "Updated Successfully"}),200
    except BaseException as Error:
        return jsonify({"Error" : f"{Error}"})


# To buy courses  in this user is login required
@app.route("/buy_course", methods = ["POST"])
@jwt_required()
def buy_course():
    try:
        data = request.get_json()

        # to check user is not missing all required field
        if not data:
            return jsonify({"Error" :"Course Id Is Required"}),400
        
        # To check is course is present or not
        if not Course.query.filter_by(id = data["course_id"]).first():
            return jsonify({"Error" : "Course Not Found"}),404
        
        # To add Buy coures n DB
        Buy_course = Course_Buy(course_id = data["course_id"], user_id = get_jwt_identity())
        db.session.add(Buy_course)
        db.session.commit()

        return jsonify({"Message" : "Course Purcase Successfully"}),200
    except BaseException as Error:
        return jsonify({
            "Error" : f"{Error}"
        })

# Data to get all courses that buy by specific user how login in it 
@app.route("/get_buy_course", methods = ["GET"])
@jwt_required()
def get_buy_course():
    try:
        # To filter course data by user id to fetch only data for course of specific user.
        data = db.session.query(Course.id).join(Course_Buy).filter(Course_Buy.user_id == get_jwt_identity()).all()

        # If user is not Buy any course then return Error 404
        if not data:
            return jsonify({"Error" : "No Course Found"}),404
        

        # Course List of users Buy courses
        buy_course_list = []
        for course in data:
            print(course[0])
            course_data = Course.query.filter_by(id = course[0]).first()
            print(course_data.name)
            # To append course deitals according to course name, price
            buy_course_list.append({
                "Buy Course ID" : course.id,
                "Course Name" :  course_data.name,
                "Course Price" : course_data.price
            })
        return jsonify({"message" : buy_course_list}),200
    except BaseException as Error:
        return jsonify({
            "Error" : f"{Error}"
        })

@app.route("/get_users", methods = ["GET"])
def get_users():
    try:
        data = User.query.all()

        users_list = []
        for user in data:
            users_list.append(
                {
                    "ID" : user.id,
                    "Name" : user.name,
                    "Email" : user.email,
                    "is_admin" : user.is_admin,
                    "Address" : user.address
                }
            )
        print(users_list)
        return jsonify({"Users" : users_list})
    except BaseException as Error:
        return jsonify({
            "Error" : f"{Error}"
        })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=11000, debug=True)
    


