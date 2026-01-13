# Secure Web Authentication System

A secure, production-style web authentication system developed using **Flask and Python**, implementing real-world security mechanisms commonly used in modern web applications.

---

## 📌 Project Description

This project provides a complete and secure authentication workflow, including user registration, login, session management, account lockout, and admin-controlled account recovery.  
It is designed to go beyond basic login systems and demonstrate backend development, database integration, and security best practices.

---

## 🚀 Key Features

- User registration and login
- Secure password hashing using **bcrypt**
- Strong password policy enforcement
- Brute-force attack prevention
- Account lockout after 3 failed login attempts
- Admin-controlled account unlock functionality
- Session-based authentication
- Protected dashboard route
- Secure logout mechanism
- SQLite database for data persistence

---

## 🛠️ Technology Stack

- **Python**
- **Flask**
- **SQLite**
- **bcrypt**
- **HTML (Jinja2 Templates)**

---

## 📂 Project Structure

secure-web-authentication/
│
├── app.py
├── login.py
├── templates/
│ ├── login.html
│ ├── register.html
│ ├── dashboard.html
│ └── admin.html
├── .gitignore
└── README.md


