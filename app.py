from flask import Blueprint, request, jsonify, session,Flask
from flask_jwt_extended import JWTManager
from models import db,User,Course,Course_Buy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_migrate import Migrate
from flask_jwt_extended import jwt_required, get_jwt_identity,verify_jwt_in_request


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///API.db'
app.config['JWT_SECRET_KEY'] = 'Atp@4466'
app.config['SECRET_KEY'] = 'Atp@4466'
db.init_app(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)


# For Sign Up or Register the User.
@app.route("/signup", methods = ['POST'])
def signup():

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


# tO Sign in user.
@app.route("/signin",methods = ["POST"])
def signin():
    data = request.get_json()

    #To Filter by email  or fetch user password
    email,password = data['email'],data['password']
    user = User.query.filter_by(email=email).first()

    #To check is user is in database or password is correct
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    #To Create JWT token
    token = create_access_token(identity=str(user.id))

    session["jwt"] = token

    return jsonify({'message': 'Login successful', 'token': token}), 200


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

    

# To get all courses in DB only admin can show this
@app.route("/get_course",methods = ["GET"])
@jwt_required()
def get_course():

    # To check Login user is admin or not
    user_is_admin = User.query.filter_by(id = get_jwt_identity()).first().is_admin
    if not user_is_admin:
        return jsonify({"message": "Only Admin Can Access"})

    # To get all courses in DB if not COurses in DB thrn Return Error
    data = Course.query.all()
    if not data:
        return jsonify({"message" : "Course Not Found"}),404
    
    return jsonify({'course' : [{
        'Course_id' : course.id, "Course_Name" : course.name, "Course_Description" : course.description}  for course in data
    ]})



# To delete course from DB only admin can delete
@app.route("/delete_course", methods= ["DELETE"])
@jwt_required()
def delete_course():


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


# To buy courses  in this user is login required
@app.route("/buy_course", methods = ["POST"])
@jwt_required()
def buy_course():
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


# Data to get all courses that buy by specific user how login in it 
@app.route("/get_buy_course", methods = ["GET"])
@jwt_required()
def get_buy_course():
    
    # To filter course data by user id to fetch only data for course of specific user
    data = db.session.query(Course.id).join(Course_Buy).filter(Course_Buy.user_id == get_jwt_identity()).all()

    # If user is not Buy any course then return Error 404
    if not data:
        return jsonify({"Error" : "No Course Found"}),404
    

    # Course List of users Buy courses
    buy_course_list = []
    for course in data:
        
        course_data = Course.query.filter_by(id = course[0]).first()
        
        buy_course_list.append({
            "Buy Course ID" : course.id,
            "Course Name" :  course_data.name,
            "Course Price" : course_data.price
        })
    return jsonify({"message" : buy_course_list}),200


if __name__ == "__main__":
    app.run(debug=True)
    


