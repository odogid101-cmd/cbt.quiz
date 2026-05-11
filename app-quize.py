import os
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

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
    
    # Add subscription + payment columns
    cur.execute("""
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS subscription_status TEXT DEFAULT 'inactive' 
          CHECK (subscription_status IN ('inactive', 'active', 'expired', 'pending')),
        ADD COLUMN IF NOT EXISTS subscription_expires TIMESTAMP,
        ADD COLUMN IF NOT EXISTS paystack_sub_ref TEXT UNIQUE,
        ADD COLUMN IF NOT EXISTS payment_method TEXT,
        ADD COLUMN IF NOT EXISTS receipt_url TEXT
    """)
    
    # Settings table for monthly price
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

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    login_field = data.get("login")
    password = data.get("password")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id, username, email, password, subscription_status, subscription_expires FROM users WHERE (username=%s OR email=%s) AND app_type='cbt_user'",
        (login_field, login_field)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    if user["subscription_status"] != 'active' or (user["subscription_expires"] and user["subscription_expires"] < datetime.utcnow()):
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
    if admin_pass != ADMIN_PASSWORD:
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
    
    if admin_pass != ADMIN_PASSWORD:
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
    
    # Send verification email
    try:
        msg = Message(
            subject="Payment Verified - Account Activated",
            recipients=[user['email']],
            body=f"Hi {user['username']},\n\nWe have just verified your payment. Your account is now active for 30 days.\n\nYou can now login and use the platform.\n\nThanks!"
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
    
    if admin_pass != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 403
    
    set_setting('monthly_price', str(price))
    return jsonify({"message": "Price updated", "price": price}), 200

@app.route("/admin/get_price", methods=["GET"])
def get_price():
    return jsonify({"price": get_setting('monthly_price', '100')}), 200

@app.route("/")
def home():
    return jsonify({"message": "CBT API Running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)