import os
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "cbtcredit.support@gmail.com")

# ... keep all your other code same ...

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
    
    # Send email via SendGrid HTTP API - works on Render
    try:
        message = Mail(
            from_email=FROM_EMAIL,
            to_emails=user['email'],
            subject="Payment Verified - Account Activated",
            plain_text_content=f"Hi {user['username']},\n\nWe have just verified your payment. Your account is now active for 30 days.\n\nYou can now login and use the platform.\n\nThanks!"
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
    except Exception as e:
        print("SendGrid error:", e)
    
    return jsonify({"message": "Payment verified and email sent"}), 200
