# =========================
# SMARTCART - FULL APP.PY
# With Cart + Razorpay + Orders + Address + Invoice
# =========================

from flask import (
    Flask, render_template, request,
    redirect, session, flash, jsonify,
    make_response, url_for
)
from flask_mail import Mail, Message
import mysql.connector
import bcrypt
import random
import os
import razorpay
import traceback
from io import BytesIO

from werkzeug.utils import secure_filename
import config

# PDF library (DAY-14)
from xhtml2pdf import pisa

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ============================================================
# EMAIL CONFIG
# ============================================================
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)

# ============================================================
# IMAGE UPLOAD FOLDERS
# ============================================================
PRODUCT_UPLOAD_FOLDER = "static/uploads/product_images"
ADMIN_UPLOAD_FOLDER = "static/uploads/admin_profiles"

app.config['PRODUCT_UPLOAD_FOLDER'] = PRODUCT_UPLOAD_FOLDER
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

os.makedirs(PRODUCT_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)

# ============================================================
# RAZORPAY CLIENT (Day 12)
# ============================================================
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

# ============================================================
# DB CONNECTION
# ============================================================
def get_db_connection():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


def get_hash_bytes(db_value):
    """Ensure bcrypt hash value is bytes."""
    if isinstance(db_value, bytes):
        return db_value
    return db_value.encode("utf-8")


# ============================================================
# HELPER: PDF GENERATION (HTML → PDF)
# ============================================================
def generate_pdf_from_html(html_string):
    """
    Uses xhtml2pdf to convert HTML string to PDF (BytesIO).
    Returns BytesIO object or None on error.
    """
    pdf = BytesIO()
    result = pisa.CreatePDF(html_string, dest=pdf)
    if result.err:
        return None
    pdf.seek(0)
    return pdf


# ============================================================
# PUBLIC ROUTES
# ============================================================
@app.route('/')
def home():
    return render_template("public/index.html")


@app.route('/about')
def about():
    return render_template("public/about.html")


@app.route('/contact')
def contact():
    return render_template("public/contact.html")


@app.route('/login')
def login_select():
    return render_template("login_select.html")


@app.route('/register')
def register_select():
    return render_template("register_select.html")


# ============================================================
# ===================== ADMIN MODULE =========================
# ============================================================

# ----------------- ADMIN SIGNUP WITH OTP --------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'GET':
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
        flash("Email already registered! Please login.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['admin_otp'] = otp

    msg = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(msg)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# ----------------- ADMIN OTP VERIFY (GET + POST) ------------
@app.route('/verify-otp', methods=['GET', 'POST'])
def admin_verify_otp():
    if request.method == 'GET':
        return render_template("admin/verify_otp.html")

    entered_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('admin_otp')) != str(entered_otp):
        flash("Invalid OTP!", "danger")
        return redirect('/verify-otp')

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO admin (name, email, password)
        VALUES (%s, %s, %s)
    """, (session['signup_name'], session['signup_email'], hashed_pw))
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('signup_name', None)
    session.pop('signup_email', None)
    session.pop('admin_otp', None)

    flash("Admin registered successfully! Please login.", "success")
    return redirect('/admin-login')


# ----------------- ADMIN LOGIN ------------------------------
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

    stored_hash = get_hash_bytes(admin['password'])

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        flash("Incorrect password!", "danger")
        return redirect('/admin-login')

    session.clear()
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']

    flash("Admin login successful!", "success")
    return redirect('/admin-dashboard')


# ----------------- ADMIN DASHBOARD --------------------------
@app.route('/admin-dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please login as Admin!", "danger")
        return redirect('/admin-login')

    return render_template("admin/dashboard.html", admin_name=session['admin_name'])


# ----------------- ADMIN LOGOUT -----------------------------
@app.route('/admin-logout')
def admin_logout():
    session.clear()
    flash("Admin logged out.", "success")
    return redirect('/admin-login')


# ----------------- ADMIN FORGOT PASSWORD --------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'GET':
        return render_template("admin/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()

    if not admin:
        flash("Email not found!", "danger")
        cursor.close()
        conn.close()
        return redirect('/forgot-password')

    reset_token = str(random.randint(100000, 999999))
    cursor.execute("UPDATE admin SET reset_token=%s WHERE email=%s",
                   (reset_token, email))
    conn.commit()
    cursor.close()
    conn.close()

    reset_link = f"http://127.0.0.1:5000/reset-password/{reset_token}"

    msg = Message(
        subject="SmartCart Admin Password Reset",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Click here to reset your password:\n{reset_link}"
    mail.send(msg)

    flash("Password reset link sent to your email.", "success")
    return redirect('/forgot-password')


# ----------------- ADMIN RESET PASSWORD (TOKEN PAGE) --------
@app.route('/reset-password/<token>')
def admin_reset_password_token(token):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email FROM admin WHERE reset_token=%s", (token,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not admin:
        flash("Invalid or expired reset link!", "danger")
        return redirect('/admin-login')

    session['reset_email'] = admin['email']
    return render_template("admin/reset_password.html")


# ----------------- ADMIN RESET PASSWORD (SUBMIT NEW) --------
@app.route('/reset-password', methods=['POST'])
def admin_reset_password_submit():
    email = session.get('reset_email')
    new_pw = request.form['password']

    if not email:
        flash("Session expired!", "danger")
        return redirect('/admin-login')

    hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE admin SET password=%s, reset_token=NULL WHERE email=%s
    """, (hashed_pw, email))
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('reset_email', None)

    flash("Password updated successfully! Please login.", "success")
    return redirect('/admin-login')


# ----------------- ADMIN PROFILE ----------------------------
@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if 'admin_id' not in session:
        flash("Please login as Admin!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE admin_id=%s", (admin_id,))
    admin = cursor.fetchone()

    if request.method == 'GET':
        cursor.close()
        conn.close()
        return render_template("admin/admin_profile.html", admin=admin)

    name = request.form['name']
    email = request.form['email']
    new_pw = request.form['password']
    image_file = request.files['profile_image']

    if new_pw.strip():
        hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_pw = admin['password']

    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        filepath = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], filename)
        image_file.save(filepath)
    else:
        filename = admin.get('profile_image')

    cursor.execute("""
        UPDATE admin SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_pw, filename, admin_id))
    conn.commit()
    cursor.close()
    conn.close()

    session['admin_name'] = name
    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')


# ----------------- ADMIN ADD PRODUCT ------------------------
@app.route('/admin/add-item', methods=['GET', 'POST'])
def admin_add_item():
    if 'admin_id' not in session:
        flash("Please login as Admin!", "danger")
        return redirect('/admin-login')

    if request.method == 'GET':
        return render_template("admin/add_item.html")

    name = request.form['name']
    desc = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    if not image_file or not image_file.filename:
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    filepath = os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], filename)
    image_file.save(filepath)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (name, description, category, price, image)
        VALUES (%s, %s, %s, %s, %s)
    """, (name, desc, category, price, filename))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')


# ----------------- ADMIN PRODUCT LIST -----------------------
@app.route('/admin/item-list')
def admin_item_list():
    if 'admin_id' not in session:
        flash("Please login as Admin!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append(f"%{search}%")

    if category:
        query += " AND category=%s"
        params.append(category)

    cursor.execute(query, params)
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/item_list.html",
                           products=products,
                           categories=categories)


# ----------------- ADMIN VIEW PRODUCT -----------------------
@app.route('/admin/view-item/<int:item_id>')
def admin_view_item(item_id):
    if 'admin_id' not in session:
        flash("Please login as Admin!", "danger")
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


# ----------------- ADMIN UPDATE PRODUCT ---------------------
@app.route('/admin/update-item/<int:item_id>', methods=['GET', 'POST'])
def admin_update_item(item_id):
    if 'admin_id' not in session:
        flash("Please login as Admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    if request.method == 'GET':
        cursor.close()
        conn.close()
        return render_template("admin/update_item.html", product=product)

    name = request.form['name']
    desc = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']
    old_image = product['image']

    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        filepath = os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], filename)
        image_file.save(filepath)

        old_path = os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], old_image)
        if os.path.exists(old_path):
            os.remove(old_path)

        final_image = filename
    else:
        final_image = old_image

    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s
    """, (name, desc, category, price, final_image, item_id))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# ----------------- ADMIN DELETE PRODUCT ---------------------
@app.route('/admin/delete-item/<int:item_id>')
def admin_delete_item(item_id):
    if 'admin_id' not in session:
        flash("Please login as Admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT image FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']
    image_path = os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], image_name)

    if os.path.exists(image_path):
        os.remove(image_path)

    cursor.execute("DELETE FROM products WHERE product_id=%s", (item_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')
# ============================================================
# ======================= USER MODULE ========================
# ============================================================

# ----------------- USER REGISTER → SEND OTP -----------------
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    exists = cursor.fetchone()
    cursor.close()
    conn.close()

    if exists:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    session['reg_name'] = name
    session['reg_email'] = email

    otp = random.randint(100000, 999999)
    session['user_otp'] = otp

    msg = Message(
        subject="SmartCart User OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Your OTP for SmartCart User Registration is: {otp}"
    mail.send(msg)

    flash("OTP sent to your email!", "success")
    return redirect('/user-verify-otp')


# ----------------- USER OTP VERIFY --------------------------
@app.route('/user-verify-otp', methods=['GET', 'POST'])
def user_verify_otp():
    if request.method == 'GET':
        return render_template("user/user_verify_otp.html")

    entered_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('user_otp')) != str(entered_otp):
        flash("Invalid OTP!", "danger")
        return redirect('/user-verify-otp')

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (name, email, password)
        VALUES (%s, %s, %s)
    """, (session['reg_name'], session['reg_email'], hashed_pw))
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('reg_name', None)
    session.pop('reg_email', None)
    session.pop('user_otp', None)

    flash("User registered successfully! Please login.", "success")
    return redirect('/user-login')


# ----------------- USER LOGIN -------------------------------
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    stored_hash = get_hash_bytes(user['password'])

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    session.clear()
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    session['cart_count'] = sum(item['quantity'] for item in session.get('cart', {}).values())

    flash("User login successful!", "success")
    return redirect('/user-dashboard')


# ----------------- USER DASHBOARD ---------------------------
@app.route('/user-dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])


# ----------------- USER LOGOUT ------------------------------
@app.route('/user-logout')
def user_logout():
    session.clear()
    flash("User logged out.", "success")
    return redirect('/user-login')


# ============================================================
# USER PRODUCTS
# ============================================================
@app.route('/user/products')
def user_products():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    search = request.args.get("search", "")
    category = request.args.get("category", "")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append(f"%{search}%")

    if category:
        query += " AND category=%s"
        params.append(category)

    cursor.execute(query, params)
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("user/user_products.html", products=products, categories=categories)


# ----------------- VIEW PRODUCT ------------------------------
@app.route('/user/product/<int:pid>')
def user_view_product(pid):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (pid,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/user_view_product.html", product=product)


# ============================================================
# CART SYSTEM (DAY 11)
# ============================================================

# Add to Cart
@app.route('/user/add-to-cart/<int:pid>')
def user_add_to_cart(pid):
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Login required"})

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (pid,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        return jsonify({"status": "error", "message": "Product not found"})

    cart = session.get("cart", {})
    pid_str = str(pid)

    if pid_str in cart:
        cart[pid_str]["quantity"] += 1
    else:
        cart[pid_str] = {
            "name": product["name"],
            "price": float(product["price"]),
            "image": product["image"],
            "quantity": 1
        }

    session["cart"] = cart
    session["cart_count"] = sum(item["quantity"] for item in cart.values())

    return jsonify({"status": "success", "cart_count": session["cart_count"]})


# View Cart
@app.route('/user/cart')
def user_cart():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get("cart", {})
    total = sum(item["price"] * item["quantity"] for item in cart.values())

    return render_template("user/user_cart.html", cart=cart, grand_total=total)


@app.route('/user/cart/increase/<pid>')
def cart_inc(pid):
    cart = session.get("cart", {})
    pid = str(pid)

    if pid in cart:
        cart[pid]["quantity"] += 1

    session["cart"] = cart
    session["cart_count"] = sum(i["quantity"] for i in cart.values())
    return redirect('/user/cart')


@app.route('/user/cart/decrease/<pid>')
def cart_dec(pid):
    cart = session.get("cart", {})
    pid = str(pid)

    if pid in cart:
        cart[pid]["quantity"] -= 1
        if cart[pid]["quantity"] <= 0:
            cart.pop(pid)

    session["cart"] = cart
    session["cart_count"] = sum(i["quantity"] for i in cart.values())
    return redirect('/user/cart')


@app.route('/user/cart/remove/<pid>')
def cart_remove(pid):
    cart = session.get("cart", {})
    pid = str(pid)

    if pid in cart:
        cart.pop(pid)

    session["cart"] = cart
    session["cart_count"] = sum(i["quantity"] for i in cart.values())
    return redirect('/user/cart')


# ============================================================
# ADDRESS SYSTEM (DAY 13)
# ============================================================
@app.route("/user/add-address", methods=["POST"])
def add_address():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect("/user-login")

    name = request.form.get("name")
    phone = request.form.get("phone")
    pincode = request.form.get("pincode")
    state = request.form.get("state")
    city = request.form.get("city")
    house = request.form.get("house")
    area = request.form.get("area")   # ✅ Correct field
    address_type = request.form.get("address_type")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO addresses (user_id, name, phone, pincode, state, city, house, area, address_type)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (session["user_id"], name, phone, pincode, state, city, house, area, address_type))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Address added successfully!", "success")
    return redirect("/user/select-address")




# -----------select Adress--------------------------------------------------------

@app.route("/user/select-address", methods=["GET", "POST"])
def select_address():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect("/user-login")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM addresses WHERE user_id=%s", (session["user_id"],))
    addresses = cursor.fetchall()
    cursor.close()
    conn.close()

    # POST → User selected an address
    if request.method == "POST":
        address_id = request.form.get("address_id")

        if not address_id:
            flash("Please select an address!", "danger")
            return redirect("/user/select-address")

        # Save selected address in session
        session["selected_address_id"] = address_id

        # Now go to Razorpay payment screen
        return redirect("/user/pay")

    # GET → show all saved addresses
    return render_template("user/select_address.html", addresses=addresses)

# ============================================================
# PAYMENT PAGE ENTRY AFTER ADDRESS SELECTION
# ============================================================
@app.route("/user/pay")
def user_pay():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect("/user-login")

    # Check if address is selected
    address_id = session.get("selected_address_id")
    if not address_id:
        flash("Please select a delivery address!", "warning")
        return redirect("/user/select-address")

    # Load cart
    cart = session.get("cart", {})
    if not cart:
        flash("Your cart is empty!", "warning")
        return redirect("/user/cart")

    # Calculate total
    total = sum(item["price"] * item["quantity"] for item in cart.values())
    razorpay_amount = int(total * 100)

    # Create Razorpay order
    order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session["razorpay_order_id"] = order["id"]

    return render_template(
        "user/payment.html",
        amount=total,
        razorpay_amount=razorpay_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=order["id"]
    )


# ============================================================
# CHECKOUT → RAZORPAY ORDER CREATION
# ============================================================

@app.route('/user/checkout/<int:address_id>')
def checkout(address_id):
    if 'user_id' not in session:
        flash("Login required!", "danger")
        return redirect('/user-login')

    session['selected_address'] = address_id

    cart = session.get("cart", {})
    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/cart')

    total = sum(item["price"] * item["quantity"] for item in cart.values())
    razorpay_amount = int(total * 100)  # convert to paise

    # Create Razorpay order
    rzp_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = rzp_order['id']

    return render_template(
        "user/payment.html",
        amount=total,
        razorpay_amount=razorpay_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=rzp_order['id']
    )
# ============================================================
# ============ DAY-13: VERIFY PAYMENT & STORE ORDER ==========
# ============================================================

# ============================================================
# VERIFY PAYMENT + STORE ORDER (FINAL WORKING VERSION)
# ============================================================
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Values from Razorpay script
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    # Validate required values
    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed!", "danger")
        return redirect('/user/cart')

    # Verify using Razorpay SDK
    try:
        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_signature": razorpay_signature
        })

    except Exception as e:
        print("Verification Error:", e)
        flash("Payment verification failed!", "danger")
        return redirect('/user/cart')

    # Get user & cart details
    user_id = session['user_id']
    cart = session.get('cart', {})

    if not cart:
        flash("Cart empty — cannot place order.", "danger")
        return redirect('/user/products')

    # Compute total
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # Get selected delivery address
    address_id = session.get("selected_address_id")

    if not address_id:
        flash("Delivery address missing!", "danger")
        return redirect("/user/select-address")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert order (WITH address_id)
        cursor.execute("""
            INSERT INTO orders (user_id, address_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            address_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            "paid"
        ))

        order_db_id = cursor.lastrowid  # newly created order ID

        # Insert order items
        for pid_str, item in cart.items():
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                order_db_id,
                int(pid_str),
                item["name"],
                item["quantity"],
                item["price"]
            ))

        conn.commit()

        # Clear cart
        session.pop("cart", None)
        session["cart_count"] = 0

        flash("Payment successful! Order placed.", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        print("Order Save Error:", e)
        flash("Error saving order!", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()


# ============================================================
# ORDER SUCCESS + MY ORDERS + TRACK ORDER
# ============================================================

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM orders
        WHERE order_id=%s AND user_id=%s
    """, (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("""
        SELECT * FROM order_items
        WHERE order_id=%s
    """, (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)


@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM orders
        WHERE user_id=%s
        ORDER BY created_at DESC
    """, (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)




# ============================================================
# ============ DAY-14: INVOICE PDF GENERATION =================
# ============================================================

from io import BytesIO
from xhtml2pdf import pisa

def generate_pdf(html):
    """
    Convert HTML string to PDF (BytesIO).
    """
    pdf = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf)
    if pisa_status.err:
        return None
    pdf.seek(0)
    return pdf

@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):
    if 'user_id' not in session:
        flash("Please login to download invoice.", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # JOIN orders + address
    cursor.execute("""
        SELECT o.*, a.name AS a_name, a.phone AS a_phone, a.pincode AS a_pincode,
               a.state AS a_state, a.city AS a_city, a.house AS a_house,
               a.area AS a_area, a.address_type AS a_type
        FROM orders o
        LEFT JOIN addresses a ON o.address_id = a.address_id
        WHERE o.order_id=%s AND o.user_id=%s
    """, (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect("/user/my-orders")

    # Generate invoice PDF
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF.", "danger")
        return redirect("/user/my-orders")

    response = make_response(pdf.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=invoice_{order_id}.pdf"
    return response


@app.route("/user/track/<int:order_id>")
def user_track_order(order_id):

    if "user_id" not in session:
        flash("Please login!", "danger")
        return redirect("/user-login")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM orders 
        WHERE order_id=%s AND user_id=%s
    """, (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found!", "danger")
        return redirect("/user/my-orders")

    return render_template("user/track_order.html", order=order)
@app.route('/user/checkout')
def user_checkout():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect("/user-login")

    cart = session.get("cart", {})
    if not cart:
        flash("Your cart is empty!", "warning")
        return redirect("/user/cart")

    grand_total = sum(item["price"] * item["quantity"] for item in cart.values())

    return render_template(
        "user/user_checkout.html",
        cart=cart,
        grand_total=grand_total
    )


# ============================================================
# RUN SERVER
# ============================================================
if __name__ == "__main__":
    app.run(debug=True)
