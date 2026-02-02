
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import sqlite3
import hashlib
import random
import time

app = Flask(__name__)
app.secret_key = "career_guidance_secret_key"

# ---------------- MAIL CONFIG ----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kaniavid@gmail.com'
app.config['MAIL_PASSWORD'] = 'qousdhqdxawxstqk'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# ---------------- HASH FUNCTION ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            email TEXT UNIQUE,
            otp TEXT,
            otp_time REAL
        )
    """)
    conn.commit()
    conn.close()


# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = hash_password(request.form["password"])

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=? AND otp IS NULL", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return render_template("dashboard.html", username=username)
    else:
        flash("Invalid credentials or account not verified")
        return redirect(url_for("home"))

# ---------------- REGISTER WITH OTP ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = hash_password(request.form["password"])

        otp = str(random.randint(100000, 999999))

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        if cursor.fetchone():
            flash("Email already registered")
            conn.close()
            return redirect(url_for("home"))

        cursor.execute(
            "INSERT INTO users (username, password, email, otp, otp_time) VALUES (?, ?, ?, ?, ?)",
            (username, password, email, otp, time.time())
        )
        conn.commit()
        conn.close()

        msg = Message('Your Registration OTP',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f'Your OTP is: {otp}'
        mail.send(msg)

        flash("OTP sent to email")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")

# ---------------- VERIFY OTP ----------------
@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        email = request.form["email"]
        entered_otp = request.form["otp"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT otp, otp_time FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            real_otp, timestamp = user

            if time.time() - timestamp > 300:
                flash("OTP expired")
                return redirect(url_for("register"))

            if entered_otp == real_otp:
                conn = sqlite3.connect("users.db")
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET otp=NULL, otp_time=NULL WHERE email=?", (email,))
                conn.commit()
                conn.close()

                flash("Account verified! Please login.")
                return redirect(url_for("home"))
            else:
                flash("Invalid OTP")

    return render_template("verify.html")

# ---------------- FORGOT PASSWORD ----------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = serializer.dumps(email, salt='password-reset')
            link = url_for('reset_with_token', token=token, _external=True)

            msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Reset link: {link}'
            mail.send(msg)

            flash("Reset link sent")
            return redirect(url_for("home"))
        else:
            flash("Email not found")

    return render_template("forgot.html")

# ---------------- RESET PASSWORD ----------------
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=600)
    except:
        return "Invalid or expired link"

    if request.method == 'POST':
        new_password = hash_password(request.form['password'])

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
        conn.commit()
        conn.close()

        flash("Password updated")
        return redirect(url_for("home"))

    return render_template("reset.html")

if __name__ == "__main__":
    app.run(debug=True)







