
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import bcrypt
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

ADMIN_KEY = "admin123"

# ---------- DATABASE ----------
def get_db():
    return sqlite3.connect("users.db")

def create_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash BLOB,
            attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

# ---------- PASSWORD ----------
def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password)
    )

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# ---------- ROUTES ----------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not is_strong_password(password):
            flash("Password must be strong (8 chars, upper, lower, digit)")
            return redirect(url_for("register"))

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password))
            )
            conn.commit()
            flash("Registered successfully. Please login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_hash, attempts, locked FROM users WHERE username=?",
            (username,)
        )
        user = cursor.fetchone()

        if not user:
            flash("Invalid username or password")
            return redirect(url_for("login"))

        password_hash, attempts, locked = user

        if locked:
            flash("Account locked. Contact admin.")
            return redirect(url_for("login"))

        if check_password(password, password_hash):
            cursor.execute(
                "UPDATE users SET attempts=0 WHERE username=?",
                (username,)
            )
            conn.commit()
            session["user"] = username     # 🔑 SESSION START
            flash("Login successful")
            return redirect(url_for("dashboard"))
        else:
            attempts += 1
            if attempts >= 3:
                cursor.execute(
                    "UPDATE users SET attempts=?, locked=1 WHERE username=?",
                    (attempts, username)
                )
                flash("Account locked after 3 failed attempts")
            else:
                cursor.execute(
                    "UPDATE users SET attempts=? WHERE username=?",
                    (attempts, username)
                )
                flash(f"Invalid password ({attempts}/3)")
            conn.commit()

        conn.close()
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Please login first")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully")
    return redirect(url_for("login"))

# ---------- ADMIN ----------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        admin_key = request.form["admin_key"]
        username = request.form["username"]

        if admin_key != ADMIN_KEY:
            flash("Invalid admin key")
            return redirect(url_for("admin"))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET attempts=0, locked=0 WHERE username=?",
            (username,)
        )
        conn.commit()
        conn.close()

        flash("Account unlocked successfully")
        return redirect(url_for("login"))

    return render_template("admin.html")

if __name__ == "__main__":
    create_db()
    app.run(debug=True)
