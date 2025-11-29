from flask import Flask, render_template, request, redirect, session, flash
from flask_mail import Mail, Message
import mysql.connector
import bcrypt
import random
import os
from werkzeug.utils import secure_filename
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


# =======================================================
#  route-1: EMAIL CONFIG
# =======================================================
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)


# =======================================================
# route -2: DB CONNECTION
# =======================================================
def get_db_connection():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


# =======================================================
# route-3:PUBLIC ROUTES
# =======================================================
@app.route('/')
def home():
    return render_template("public/index.html")

@app.route('/about')
def about():
    return render_template("public/about.html")

@app.route('/contact')
def contact():
    return render_template("public/contact.html")


# =======================================================
# route-4 : SIGNUP → SEND OTP
# =======================================================
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    exists = cursor.fetchone()
    cursor.close()
    conn.close()

    if exists:
        flash("Email already registered. Please login.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    msg = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# =======================================================
# route-5: OTP PAGE (GET)
# =======================================================
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


# =======================================================
# route-6 : OTP → REGISTER ADMIN
# =======================================================
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP!", "danger")
        return redirect('/verify-otp')

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (%s, %s, %s)",
        (session['signup_name'], session['signup_email'], hashed_pw)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Registered successfully! Please login.", "success")
    return redirect('/admin-login')


# =======================================================
# route-7 : LOGIN
# =======================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not admin:
        flash("Email not found!", "danger")
        return redirect('/admin-login')

    if not bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# =======================================================
# route-8 : DASHBOARD
# =======================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    return render_template("admin/dashboard.html", admin_name=session['admin_name'])


# =======================================================
# route-9 : LOGOUT
# =======================================================
@app.route('/admin-logout')
def admin_logout():
    session.clear()
    flash("Logged out!", "success")
    return redirect('/admin-login')


# =======================================================
# route- 10 : FORGOT PASSWORD → SEND RESET LINK
# =======================================================
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == "GET":
        return render_template("admin/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()

    if not admin:
        flash("Email not found!", "danger")
        return redirect('/forgot-password')

    reset_token = str(random.randint(100000, 999999))

    cursor.execute("UPDATE admin SET reset_token=%s WHERE email=%s", (reset_token, email))
    conn.commit()
    cursor.close()
    conn.close()

    reset_link = f"http://127.0.0.1:5000/reset-password/{reset_token}"

    msg = Message(
        subject="SmartCart Reset Password",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Click here to reset your password:\n\n{reset_link}"
    mail.send(msg)

    flash("Reset link sent to your email!", "success")
    return redirect('/forgot-password')


# =======================================================
# route-11 :RESET PASSWORD PAGE (GET)
# =======================================================
@app.route('/reset-password/<token>', methods=['GET'])
def reset_password(token):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email FROM admin WHERE reset_token=%s", (token,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not admin:
        flash("Invalid or expired link!", "danger")
        return redirect('/admin-login')

    session['reset_email'] = admin['email']

    return render_template("admin/reset_password.html")


# =======================================================
# route-12 : RESET PASSWORD ACTION (POST) — FIXED
# =======================================================
@app.route('/reset-password', methods=['POST'])
def update_password():

    new_password = request.form['password']
    email = session.get('reset_email')

    if not email:
        flash("Session expired!", "danger")
        return redirect('/admin-login')

    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE admin SET password=%s, reset_token=NULL WHERE email=%s",
        (hashed_pw, email)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('reset_email', None)

    flash("Password updated! Please login.", "success")
    return redirect('/admin-login')


# =======================================================
# route-13 : PRODUCT IMAGE PATH
# =======================================================
UPLOAD_FOLDER = "static/uploads/product_images"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# =======================================================
# route-14 : ADD ITEM (GET)
# =======================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# =======================================================
# route-15 : ADD ITEM (POST)
# =======================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    name = request.form['name']
    desc = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    if image_file.filename == "":
        flash("Please upload an image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, description, category, price, image) VALUES (%s, %s, %s, %s, %s)",
        (name, desc, category, price, filename)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product Added!", "success")
    return redirect('/admin/add-item')


# =======================================================
# route-16 : ITEM LIST
# =======================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/item_list.html", products=products)


# =======================================================
# route-17 : VIEW SINGLE ITEM
# =======================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)

#Route: /admin/update-item/<id> (GET)
# =================================================================
# ROUTE-18: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


#Route: /admin/update-item/<id> (POST)
# =================================================================
# ROUTE-19: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s
    """, (name, description, category, price, final_image_name, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')

# =======================================================
# RUN SERVER
# =======================================================
if __name__ == "__main__":
    app.run(debug=True)
