"""
Routes and views for the flask application.
"""
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
from flask import send_file
from flask import Flask, render_template, request, redirect, url_for, session
import flask_mysqldb
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re

app = Flask(__name__)

app.secret_key = 'xyzsdfg'

app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'login'

mysql = MySQL(app)


def encrypt(key, file):
    global imageRes, enc_file
    password = hashlib.sha256(key.encode('utf-8')).digest()

    if (('.JPG' in file) or ('.jpg' in file) or ('.PNG' in file) or ('.png' in file)) and (
            '.enc' not in file):
        input_file = open(file, "rb")
        input_data = input_file.read()
        input_file.close()

        cfb_cipher = AES.new(password, AES.MODE_CFB, 'This is an IV456'.encode("utf8"))
        enc_data = cfb_cipher.encrypt(input_data)

        enc_file = open("enc.jpg", "wb")
        imageRes = "enc.jpg"
        enc_file.write(enc_data)
        enc_file.close()

    return key, imageRes


def decrypt(key, file):
    global imageFile, imageDec
    password = hashlib.sha256(key.encode('utf-8')).digest()

    if '.jpg' in file:
        enc_file2 = open(file, "rb")
        enc_data2 = enc_file2.read()
        enc_file2.close()

        cfb_decipher = AES.new(password, AES.MODE_CFB, 'This is an IV456'.encode("utf8"))
        plain_data = (cfb_decipher.decrypt(enc_data2))

        dec_file = open("dec.jpg", "wb")
        imageDec = "dec.jpg"
        dec_file.write(plain_data)
        dec_file.close()

    return imageDec


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    mesage = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = % s AND password = % s', (email, password,))
        user = cursor.fetchone()
        if user:
            session['loggedin'] = True
            session['userid'] = user['userid']
            session['name'] = user['name']
            session['email'] = user['email']
            mesage = 'Logged in successfully !'
            return render_template('user_page.html', mesage=mesage)
        else:
            mesage = 'Please enter correct email / password !'
    return render_template('login.html', mesage=mesage)


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    mesage = ''
    if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'cpassword' in request.form and 'email' in request.form:
        userName = request.form['name']
        password = request.form['password']
        email = request.form['email']
        cpassword = request.form['cpassword']
        if password == cpassword:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user WHERE email = % s', (email,))
            account = cursor.fetchone()
            if account:
                mesage = 'Account already exists !'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                mesage = 'Invalid email address !'
            elif not userName or not password or not email:
                mesage = 'Please fill out the form !'
            else:
                cursor.execute('INSERT INTO user VALUES (NULL, % s, % s, % s)', (userName, email, password,))
                mysql.connection.commit()
                mesage = 'You have successfully registered ! Proceed with Log In !'
    elif request.method == 'POST':
        mesage = 'Please fill out the form !'
    return render_template('signup.html', mesage=mesage)


@app.route('/home')
def home():
    """Renders the home page."""
    return render_template(
        'index.html',
        title='Home Page',
        year=datetime.now().year,
    )


@app.route('/user_page')
def user_page():
    """Renders the user page."""
    return render_template(
        'user_page.html',
        title='User Page',
        year=datetime.now().year,
    )


@app.route('/contact')
def contact():
    """Renders the contact page."""
    return render_template(
        'contact.html',
        title='Decrypt',
        year=datetime.now().year,
        message='Upload your encrypted image along with the key'
    )


@app.route('/about')
def about():
    """Renders the about page."""
    return render_template(
        'about.html',
        title='Encrypt',
        year=datetime.now().year,
        message='Upload the image here'
    )


@app.route('/contact1', methods=['POST'])
def contact1():
    if request.method == 'POST':
        global f, key
        f = request.files['file']
        f.save(f.filename)
        key = request.form.get('key')
        image = decrypt(key, f.filename)
        return render_template('contact1.html',
                               title='Decrypted',
                               year=datetime.now().year,
                               message='This is your Decrypted image', name=f.filename, images=image)


@app.route('/about1', methods=['POST'])
def about1():
    if request.method == 'POST':
        global f, key

        key = request.form.get('key')
        f = request.files['file']
        f.save(f.filename)
        key, image = encrypt(key, f.filename)
        return render_template('about1.html',
                               title='Encrypted',
                               year=datetime.now().year,
                               message='This is your encrypted image', name=f.filename, images=image)


@app.route('/Encrypted-Image-By-VARS')
def Encrypted_Image():
    return send_file("../enc.jpg")


@app.route('/Decrypted-Image-By-VARS')
def return_file1():
    return send_file("../dec.jpg")


if __name__ == '__main__':
    app.run()