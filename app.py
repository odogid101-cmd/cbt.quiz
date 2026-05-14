from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)  # Allow your frontend to call this API

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")  # Set this in Render

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            app_type TEXT DEFAULT 'cbt_user',
            subscription_status TEXT DEFAULT 'inactive' 
                CHECK (subscription_status IN ('inactive', 'active', 'expired', 'pending')),
            subscription_expires TIMESTAMP,
            paystack_sub_ref TEXT UNIQUE,
            payment_method TEXT,
            receipt_url TEXT,
            reset_token TEXT,
            reset_token_expires TIMESTAMP,
            reset_attempts INT DEFAULT 0,
            is_locked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # App settings
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # Questions table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            quiz_title TEXT,
            question TEXT,
            option_a TEXT,
            option_b TEXT,
            option_c TEXT,
            option_d TEXT,
            correct_answer TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # Default monthly price
    cur.execute("""
        INSERT INTO app_settings (key, value) VALUES ('monthly_price', '1000')
        ON CONFLICT (key) DO NOTHING
    """)

    conn.commit()
    cur.close()
    conn.close()

def get_setting(key, default=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT value FROM app_settings WHERE key=%s", (key,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row["value"] if row else default

@app.route("/")
def home():
    return jsonify({"status": "ok", "message": "CBT API running"})

# ---------- AUTH ROUTES ----------

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    hashed = generate_password_hash(password)
    amount = get_setting("monthly_price", "1000")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (username, email, password, app_type, subscription_status)
            VALUES (%s, %s, %s, 'cbt_user', 'inactive')
            RETURNING user_id
        """, (username, email, hashed))
        user_id = cur.fetchone()["user_id"]
        conn.commit()
        return jsonify({
            "message": "Account created",
            "user_id": user_id,
            "amount": amount
        }), 201
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Username or email already exists"}), 400
    finally:
        cur.close()
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    login_field = data.get("login")
    password = data.get("password")
    amount = get_setting("monthly_price", "1000")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id, username, email, password, role, subscription_status, 
               subscription_expires, is_locked 
        FROM users 
        WHERE (username=%s OR email=%s) AND app_type='cbt_user'
    """, (login_field, login_field))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    if user["is_locked"]:
        return jsonify({"error": "Account locked. Contact admin"}), 403

    # Check subscription for non-admin users
    if user["role"] != 'admin':
        if user["subscription_status"] == 'expired':
            return jsonify({
                "error": "Subscription expired",
                "subscription_status": 'expired',
                "user_id": user["user_id"],
                "amount": amount
            }), 403
        if user["subscription_status"] != 'active':
            return jsonify({
                "error": "Subscription inactive",
                "subscription_status": 'inactive',
                "user_id": user["user_id"],
                "amount": amount
            }), 403

    return jsonify({
        "message": "Login successful",
        "user_id": user["user_id"],
        "user": {
            "user_id": user["user_id"], 
            "username": user["username"],
            "role": user["role"]
        },
        "subscription_status": user["subscription_status"]
    }), 200

# ---------- QUIZ CREATOR ROUTES ----------

@app.route("/admin/add_questions_bulk", methods=["POST"])
def add_questions_bulk():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    questions = data.get("questions")

    if not user_id or not questions:
        return jsonify({"error": "Missing user_id or questions"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Check access: admin or active subscription
    cur.execute("SELECT role, subscription_status FROM users WHERE user_id=%s", (user_id,))
    user = cur.fetchone()
    if not user or (user["role"] != 'admin' and user["subscription_status"] != 'active'):
        cur.close()
        conn.close()
        return jsonify({"error": "Unauthorized. Pay first or contact admin"}), 403

    try:
        for q in questions:
            cur.execute("""
                INSERT INTO questions (user_id, quiz_title, question, option_a, option_b, option_c, option_d, correct_answer)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                user_id,
                q.get("title"),
                q.get("question"),
                q.get("option_a"),
                q.get("option_b"),
                q.get("option_c"),
                q.get("option_d"),
                q.get("correct_answer")
            ))
        conn.commit()
        return jsonify({"message": f"{len(questions)} questions added successfully"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

# ---------- SUPER ADMIN MONITOR ROUTES ----------

def verify_admin_password(password):
    return password == ADMIN_PASSWORD

@app.route("/admin/pending_payments", methods=["GET"])
def pending_payments():
    password = request.args.get("admin_password")
    if not verify_admin_password(password):
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id, username, email, receipt_url, created_at 
        FROM users 
        WHERE subscription_status='pending' AND receipt_url IS NOT NULL
        ORDER BY created_at DESC
    """)
    payments = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(payments), 200

@app.route("/admin/verify_payment", methods=["POST"])
def verify_payment():
    data = request.get_json() or {}
    if not verify_admin_password(data.get("admin_password")):
        return jsonify({"error": "Unauthorized"}), 403

    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    expires = datetime.utcnow() + timedelta(days=30)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users 
        SET subscription_status='active', subscription_expires=%s, payment_method='bank_transfer'
        WHERE user_id=%s
    """, (expires, user_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Payment verified. Subscription activated"}), 200

@app.route("/admin/list_admins", methods=["GET"])
def list_admins():
    password = request.args.get("admin_password")
    if not verify_admin_password(password):
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, username, email FROM users WHERE role='admin' ORDER BY user_id")
    admins = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(admins), 200

@app.route("/admin/create_admin", methods=["POST"])
def create_admin():
    data = request.get_json() or {}
    if not verify_admin_password(data.get("admin_password")):
        return jsonify({"error": "Unauthorized"}), 403

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    if not all([username, email, password]):
        return jsonify({"error": "All fields required"}), 400

    hashed = generate_password_hash(password)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (username, email, password, role, subscription_status, app_type)
            VALUES (%s, %s, %s, 'admin', 'active', 'cbt_user')
        """, (username, email, hashed))
        conn.commit()
        return jsonify({"message": "Admin created"}), 201
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Username or email exists"}), 400
    finally:
        cur.close()
        conn.close()

@app.route("/admin/delete_admin", methods=["POST"])
def delete_admin():
    data = request.get_json() or {}
    if not verify_admin_password(data.get("admin_password")):
        return jsonify({"error": "Unauthorized"}), 403

    user_id = data.get("user_id")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE user_id=%s AND role='admin'", (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Admin deleted"}), 200

@app.route("/admin/reset_admin_password", methods=["POST"])
def reset_admin_password():
    data = request.get_json() or {}
    if not verify_admin_password(data.get("admin_password")):
        return jsonify({"error": "Unauthorized"}), 403

    user_id = data.get("user_id")
    new_password = data.get("new_password")
    if not user_id or not new_password:
        return jsonify({"error": "user_id and new_password required"}), 400

    hashed = generate_password_hash(new_password)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password=%s WHERE user_id=%s AND role='admin'", (hashed, user_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Password reset"}), 200

# ---------- RUN ----------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
