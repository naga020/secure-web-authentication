import sqlite3
import bcrypt
import getpass
import re

# ---------------- DATABASE SETUP ----------------
def create_db():
    conn = sqlite3.connect("users.db")
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

# ---------------- PASSWORD SECURITY ----------------
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# ---------------- AUDIT LOGGING ----------------
def log_event(username, event):
    with open("audit.log", "a") as f:
        f.write(f"{username} : {event}\n")

# ---------------- REGISTER ----------------
def register():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    if not is_strong_password(password):
        print("❌ Password must be 8+ chars with upper, lower, and digit")
        return

    password_hash = hash_password(password)

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        print("✅ User registered successfully")
    except sqlite3.IntegrityError:
        print("❌ Username already exists")
    finally:
        conn.close()

# ---------------- LOGIN ----------------
def login():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, attempts, locked FROM users WHERE username=?",
        (username,)
    )
    user = cursor.fetchone()

    if not user:
        print("❌ Invalid username or password")
        log_event(username, "LOGIN FAILED")
        conn.close()
        return

    password_hash, attempts, locked = user

    if locked:
        print("🚫 Account locked. Contact admin.")
        log_event(username, "LOGIN BLOCKED - ACCOUNT LOCKED")
        conn.close()
        return

    if check_password(password, password_hash):
        cursor.execute(
            "UPDATE users SET attempts=0 WHERE username=?",
            (username,)
        )
        conn.commit()
        print("✅ Login successful")
        log_event(username, "LOGIN SUCCESS")
    else:
        attempts += 1
        if attempts >= 3:
            cursor.execute(
                "UPDATE users SET attempts=?, locked=1 WHERE username=?",
                (attempts, username)
            )
            print("🚫 Account locked after 3 failed attempts")
            log_event(username, "ACCOUNT LOCKED")
        else:
            cursor.execute(
                "UPDATE users SET attempts=? WHERE username=?",
                (attempts, username)
            )
            print(f"❌ Invalid password ({attempts}/3 attempts)")
            log_event(username, "LOGIN FAILED")
        conn.commit()

    conn.close()

# ---------------- ADMIN UNLOCK ----------------
def admin_unlock():
    admin_key = getpass.getpass("Enter admin key: ")

    if admin_key != "admin123":
        print("❌ Invalid admin key")
        return

    username = input("Enter username to unlock: ")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET locked=0, attempts=0 WHERE username=?",
        (username,)
    )
    conn.commit()
    conn.close()

    print("✅ Account unlocked successfully")
    log_event(username, "ACCOUNT UNLOCKED BY ADMIN")

# ---------------- MAIN MENU ----------------
def main():
    create_db()

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Admin Unlock")
        print("4. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            admin_unlock()
        elif choice == "4":
            break
        else:
            print("❌ Invalid choice")

main()
