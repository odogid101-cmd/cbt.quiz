import os
import requests
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.sendgrid.net')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('FROM_EMAIL', 'cbtcredit.support@gmail.com')
mail = Mail(app)

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, sslmode="require")

def get_setting(key, default=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT value FROM app_settings WHERE key=%s", (key,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row['value'] if row else default

def set_setting(key, value):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO app_settings (key, value) VALUES (%s, %s)
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
    """, (key, value))
    conn.commit()
    cur.close()
    conn.close()

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Create users table if it doesn't exist
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            full_name TEXT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # Add missing columns if they don't exist
    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS app_type TEXT DEFAULT 'cbt_user',
        ADD COLUMN IF NOT EXISTS subscription_status TEXT DEFAULT 'inactive'
          CHECK (subscription_status IN ('inactive', 'active', 'expired', 'pending')),
        ADD COLUMN IF NOT EXISTS subscription_expires TIMESTAMP,
        ADD COLUMN IF NOT EXISTS paystack_sub_ref TEXT UNIQUE,
        ADD COLUMN IF NOT EXISTS payment_method TEXT,
        ADD COLUMN IF NOT EXISTS receipt_url TEXT,
        ADD COLUMN IF NOT EXISTS reset_token TEXT,
        ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP,
        ADD COLUMN IF NOT EXISTS reset_attempts INT DEFAULT 0,
        ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cur.execute("""
        INSERT INTO app_settings (key, value) VALUES ('monthly_price', '100')
        ON CONFLICT (key) DO NOTHING
    """)

    conn.commit()
    cur.close()
    conn.close()

init_db()

# ============ AUTH ============
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    required = ["username", "email", "password"]
    if not all(data.get(x) for x in required):
        return jsonify({"error": "Missing fields"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (full_name, username, email, password, role, app_type, subscription_status)
            VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING user_id
        """, (
            data["username"], data["username"], data["email"],
            generate_password_hash(data["password"]),
            'user', 'cbt_user', 'inactive'
        ))
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({
            "message": "Account created. Proceed to payment",
            "user_id": user["user_id"],
            "amount": get_setting('monthly_price', '100')
        }), 201
    except IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        print("Register error:", e)
        return jsonify({"error": "Server error"}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    login_field = data.get("login")
    password = data.get("password")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id, username, email, password, subscription_status, subscription_expires, is_locked FROM users WHERE (username=%s OR email=%s) AND app_type='cbt_user'",
        (login_field, login_field)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    if user["is_locked"]:
        return jsonify({"error": "Account locked. Contact admin to reset password"}), 403

    if user["subscription_status"]!= 'active' or (user["subscription_expires"] and user["subscription_expires"] < datetime.utcnow()):
        return jsonify({
            "error": "Subscription inactive or expired",
            "subscription_status": user["subscription_status"],
            "amount": get_setting('monthly_price', '100')
        }), 403

    return jsonify({
        "message": "Login successful",
        "user_id": user["user_id"],
        "user": {"user_id": user["user_id"], "username": user["username"]}
    }), 200

# ============ FORGOT PASSWORD WITH LOCKOUT ============
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, email, is_locked FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({"message": "If that email exists, a reset code has been sent"}), 200

    if user["is_locked"]:
        cur.close()
        conn.close()
        return jsonify({"error": "Account locked. Contact admin"}), 403

    code = str(random.randint(100000, 999999))
    expires = datetime.utcnow() + timedelta(minutes=15)

    cur.execute("""
        UPDATE users
        SET reset_token=%s, reset_token_expires=%s, reset_attempts=0
        WHERE user_id=%s
    """, (code, expires, user["user_id"]))
    conn.commit()
    cur.close()
    conn.close()

    try:
        msg = Message(
            subject="Your Password Reset Code",
            recipients=[email],
            html=f"""
            <h3>Password Reset Request</h3>
            <p>Your reset code is: <b style="font-size:24px; letter-spacing:3px;">{code}</b></p>
            <p>This code expires in 15 minutes. 5 wrong attempts will lock your account.</p>
            """
        )
        mail.send(msg)
        return jsonify({"message": "If that email exists, a reset code has been sent"}), 200
    except Exception as e:
        print("Mail error:", e)
        return jsonify({"error": "Failed to send email"}), 500

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    token = data.get("token")
    password = data.get("password")

    if not token or not password:
        return jsonify({"error": "Code and password required"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id, reset_attempts, is_locked, reset_token FROM users
        WHERE reset_token=%s AND reset_token_expires > %s
    """, (token, datetime.utcnow()))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({"error": "Invalid or expired code"}), 400

    if user["is_locked"]:
        cur.close()
        conn.close()
        return jsonify({"error": "Account locked. Contact admin"}), 403

    # Wrong code
    if str(token)!= str(user["reset_token"]):
        attempts = user["reset_attempts"] + 1
        lock = attempts >= 5
        cur.execute("""
            UPDATE users
            SET reset_attempts=%s, is_locked=%s
            WHERE user_id=%s
        """, (attempts, lock, user["user_id"]))
        conn.commit()
        cur.close()
        conn.close()
        if lock:
            return jsonify({"error": "Too many failed attempts. Account locked. Contact admin"}), 403
        return jsonify({"error": f"Invalid code. {5 - attempts} attempts left"}), 400

    # Correct code
    hashed_pw = generate_password_hash(password)
    cur.execute("""
        UPDATE users
        SET password=%s, reset_token=NULL, reset_token_expires=NULL, reset_attempts=0, is_locked=FALSE
        WHERE user_id=%s
    """, (hashed_pw, user["user_id"]))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Password updated successfully"}), 200

# List all admins
@app.route("/admin/list_admins", methods=["GET"])
def list_admins():
    admin_pass = request.args.get("admin_password")
    if admin_pass != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, username, email FROM users WHERE role='admin'")
    admins = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(admins), 200

# Create new admin
@app.route("/admin/create_admin", methods=["POST"])
def create_admin():
    data = request.get_json() or {}
    if data.get("admin_password") != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, email, password, role, app_type, subscription_status)
            VALUES (%s,%s,%s,'admin','cbt_user','active')
            RETURNING user_id
        """, (data["username"], data["email"], generate_password_hash(data["password"])))
        user_id = cur.fetchone()["user_id"]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Admin created", "user_id": user_id}), 201
    except IntegrityError:
        return jsonify({"error": "Email or username exists"}), 400

# Delete admin
@app.route("/admin/delete_admin", methods=["POST"])
def delete_admin():
    data = request.get_json() or {}
    if data.get("admin_password") != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE user_id=%s AND role='admin'", (data["user_id"],))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Admin deleted"}), 200

# Reset admin password
@app.route("/admin/reset_admin_password", methods=["POST"])
def reset_admin_password():
    data = request.get_json() or {}
    if data.get("admin_password") != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    hashed = generate_password_hash(data["new_password"])
    cur.execute("UPDATE users SET password=%s WHERE user_id=%s AND role='admin'", 
                (hashed, data["user_id"]))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Password updated"}), 200

# ============ ADMIN RESET ============
@app.route("/admin/reset_user_password", methods=["POST"])
def admin_reset_user_password():
    data = request.get_json() or {}
    email = data.get("email")
    new_password = data.get("new_password")
    admin_pass = data.get("admin_password")

    if admin_pass!= ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403

    if not email or not new_password:
        return jsonify({"error": "Email and new password required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    hashed_pw = generate_password_hash(new_password)
    cur.execute("""
        UPDATE users
        SET password=%s, reset_token=NULL, reset_token_expires=NULL, reset_attempts=0, is_locked=FALSE
        WHERE email=%s
        RETURNING user_id
    """, (hashed_pw, email))
    user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Password reset successfully"}), 200

# ============ PAYSTACK ============
@app.route("/paystack/initialize", methods=["POST"])
def paystack_initialize():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    email = data.get("email")
    amount = int(get_setting('monthly_price', '100')) * 100
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "email": email,
        "amount": amount,
        "metadata": {"user_id": user_id},
        "callback_url": data.get("callback_url")
    }
    try:
        res = requests.post("https://api.paystack.co/transaction/initialize", json=payload, headers=headers)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/paystack/verify/<reference>", methods=["GET"])
def paystack_verify(reference):
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    res = requests.get(f"https://api.paystack.co/transaction/verify/{reference}", headers=headers)
    data = res.json()
    if data.get("status") and data["data"]["status"] == "success":
        user_id = data["data"]["metadata"].get("user_id")
        expires = datetime.utcnow() + timedelta(days=30)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE users
            SET subscription_status='active',
                subscription_expires=%s,
                paystack_sub_ref=%s,
                payment_method='paystack'
            WHERE user_id=%s
        """, (expires, reference, user_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success", "expires": expires.isoformat()}), 200
    return jsonify({"status": "failed"}), 400

# ============ BANK TRANSFER ============
@app.route("/banktransfer/submit", methods=["POST"])
def bank_transfer_submit():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    receipt_url = data.get("receipt_url")
    if not user_id or not receipt_url:
        return jsonify({"error": "Missing user_id or receipt_url"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET subscription_status='pending',
            payment_method='bank_transfer',
            receipt_url=%s
        WHERE user_id=%s
    """, (receipt_url, user_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Receipt submitted. Awaiting admin verification"}), 200

@app.route("/admin/pending_payments", methods=["GET"])
def pending_payments():
    admin_pass = request.args.get("admin_password")
    if admin_pass!= ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id, username, email, receipt_url, created_at
        FROM users
        WHERE subscription_status='pending' AND payment_method='bank_transfer'
        ORDER BY created_at DESC
    """)
    payments = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(payments), 200

@app.route("/admin/verify_payment", methods=["POST"])
def verify_payment():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    admin_pass = data.get("admin_password")
    if admin_pass!= ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    expires = datetime.utcnow() + timedelta(days=30)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET subscription_status='active',
            subscription_expires=%s
        WHERE user_id=%s
        RETURNING email, username
    """, (expires, user_id))
    user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    try:
        msg = Message(
            subject="Payment Verified - Account Activated",
            recipients=[user['email']],
            body=f"Hi {user['username']},\n\nYour account is now active for 30 days.\n\nThanks!"
        )
        mail.send(msg)
    except Exception as e:
        print("Email error:", e)
    return jsonify({"message": "Payment verified and email sent"}), 200

@app.route("/admin/set_price", methods=["POST"])
def set_price():
    data = request.get_json() or {}
    price = data.get("price")
    admin_pass = data.get("admin_password")
    if admin_pass!= ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    set_setting('monthly_price', str(price))
    return jsonify({"message": "Price updated", "price": price}), 200

@app.route("/admin/get_price", methods=["GET"])
def get_price():
    return jsonify({"price": get_setting('monthly_price', '100')}), 200

@app.route("/")
def home():
    return jsonify({"message": "CBT Quiz API Running smoothly"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
