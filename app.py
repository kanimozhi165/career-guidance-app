
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

import hashlib

from flask import Flask, render_template, request

from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3




def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


app = Flask(__name__)


app.secret_key = "career_guidance_secret_key"

app.config['PREFERRED_URL_SCHEME'] = 'https'


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kaniavid@gmail.com'
app.config['MAIL_PASSWORD'] = 'qousdhqdxawxstqk'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

app.secret_key = "career_secret"

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- ROUTES ----------

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = hash_password(request.form["password"])


    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return render_template("dashboard.html", username=username)

    else:
        flash("Invalid username or password")
        return redirect(url_for("home"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

       username = request.form["username"]
       email = request.form["email"]
       password = hash_password(request.form["password"])


       try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, password, email))

            conn.commit()
            conn.close()
            flash("Registration successful! Please login.")
            return redirect(url_for("home"))
       except:
            flash("Username already exists!")
            return redirect(url_for("register"))

    return render_template("register.html")

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
           
            link = url_for('reset_with_token', token=token, _external=True, _scheme='https')

            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])

            msg.body = f'Click the link to reset your password: {link}'
            mail.send(msg)

            flash("Password reset link sent to your email.")
            return redirect(url_for("home"))
        else:
            flash("Email not found!")
            return redirect(url_for("forgot_password"))

    return render_template("forgot.html")

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=600)
    except:
        return "Link expired or invalid."

    if request.method == 'POST':
        new_password = hash_password(request.form['password'])

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE username=?", (new_password, email))
        conn.commit()
        conn.close()

        flash("Password reset successful. Please login.")
        return redirect(url_for('home'))

    return render_template("reset.html")


if __name__ == "__main__":
    app.run(debug=True)



