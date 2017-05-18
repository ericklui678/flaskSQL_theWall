from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
import md5
import re
import os, binascii
app = Flask(__name__)
mysql = MySQLConnector(app,'wall') #database name
app.secret_key = 'ThisIsSecret'
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX =re.compile('^[A-z]+$')

@app.route('/')
def index():
    # If it's the user's first time on the site, display the login page
    if session.get('userID') == None:
        return render_template('index.html')
    # else if there's still session data, stay on wall page
    else:
        return redirect('/wall')

@app.route('/create', methods=['POST'])
def create():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm']
    # count correct fields
    count = 0
    # Validate first_name
    if len(first_name) <= 2:
        flash('First name must be at least 2 letters')
    elif not NAME_REGEX.match(first_name):
        flash('First name must only contain alphabet')
    else:
        print 'SUCCESS FIRST NAME'
        count += 1

    # Validate last_name
    if len(last_name) <= 2:
        flash('Last name must be at least 2 letters')
    elif not NAME_REGEX.match(last_name):
        flash('Last name must only contain alphabet')
    else:
        print 'SUCCESS LAST NAME'
        count += 1

    # Validate email
    if len(request.form['email']) < 1:
        flash("Email cannot be blank")
    elif not EMAIL_REGEX.match(email):
        flash('Invalid email format')
    else:
        print 'SUCCESS EMAIL'
        count += 1

    # Validate password
    if len(password) < 8:
        flash('Password must be at least 8 characters')
    else:
        print 'SUCCESS PASSWORD'
        count += 1

    # Validate confirm password
    if password != confirm or len(password) < 1:
        flash('Passwords do not match')
        return redirect('/')
    else:
        print 'SUCCESS CONFIRM'
        count += 1

    # if all fields have correct input
    if count == 5:
        # SELECT EXISTS returns boolean whether email already exists in db
        query = "SELECT EXISTS (SELECT * FROM users WHERE email = '" + email + "')"
        output = mysql.query_db(query)
        for dict in output:
            for key in dict:
                if dict[key] == 1:   # if email exists in database
                    flash('Email has already been registered')
                    return redirect('/')
        # create random salt value
        salt = binascii.b2a_hex(os.urandom(15))
        # hash password with salt
        hashed_pw = md5.new(password + salt).hexdigest()
        # query for inserting data
        query = "INSERT INTO users(first_name, last_name, email, salt, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :salt, :password, NOW(), NOW())"
        # data will consists of whatever the user typed in
        data = {'first_name': first_name, 'last_name': last_name, 'email': email, 'salt': salt, 'password': hashed_pw}
        # run the query with data
        session['userID'] = mysql.query_db(query, data)
        session['name'] = first_name
        print 'SUCCESSFULLY REGISTERED'
        # session['userID'] = output[0]['first_name']

    return redirect('/wall')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    # query to return email if found on db
    query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    data = {'email': email}
    output = mysql.query_db(query, data)
    print output
    # if the email is found
    if len(output) != 0:
        encrypted_password = md5.new(password + output[0]['salt']).hexdigest()
        # if the hashed passwords match
        if output[0]['password'] == encrypted_password:
            session['userID'] = output[0]['id']
            session['name'] = output[0]['first_name']
            return redirect('/wall')
        else:
            flash('PASSWORD INCORRECT')
    else:
        flash('EMAIL DOES NOT EXIST IN DB')

    return redirect('/')

@app.route('/logoff', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')


@app.route('/wall')
def wall():
    query = "SELECT CONCAT_WS(' ', users.first_name, users.last_name) as name, DATE_FORMAT(messages.created_at, '%M %d %Y %l:%i %p') as date, messages.message FROM messages LEFT JOIN users ON messages.user_id = users.id ORDER BY messages.created_at DESC"
    wall_messages = mysql.query_db(query)
    return render_template('wall.html', wall_messages=wall_messages)

@app.route('/message', methods=['POST'])
def message():
    message = request.form['message_box']

    query = "INSERT INTO messages(user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW())"
    data = {'user_id': session['userID'], 'message': message}
    mysql.query_db(query, data)

    return redirect('/wall')


# INSERT INTO messages (user_id, message, created_at, updated_at)
# VALUES (1, 'this is a test message', NOW(), NOW())

# USE THIS STUFF LATER ----------------------------------------------------------------
# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form['email']
#     password = request.form['password']
#     # query to return email if found on db
#     query = "SELECT * FROM users WHERE email = :email LIMIT 1"
#     data = {'email': email}
#     output = mysql.query_db(query, data)
#     print output
#     # if the email is found
#     if len(output) != 0:
#         encrypted_password = md5.new(password + output[0]['salt']).hexdigest()
#         # if the hashed passwords match
#         if output[0]['password'] == encrypted_password:
#             session['userID'] = output[0]['id']
#             print session['userID']
#             return redirect('/success')se
#         else:
#             flash('PASSWORD INCORRECT')
#     else:
#         flash('EMAIL DOES NOT EXIST IN DB')
#
#     return redirect('/')
#
# @app.route('/success')
# def success():
#     return render_template('success.html')
#
# app.run(debug = True)

app.run(debug = True)
