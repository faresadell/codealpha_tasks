"""
UserPortal - Sample Application (POST-AUDIT / REMEDIATED VERSION)
====================================================================
CodeAlpha Cyber Security Internship - Task 3: Secure Coding Review

This is the remediated version of app_before/app.py. Every vulnerability
documented in SECURITY_REVIEW.md has been fixed here. Comments mark each
fix and reference the corresponding finding number from the report.
"""

import os
import sqlite3
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, request, redirect, session, render_template_string, send_from_directory

app = Flask(__name__)

# --- Fix 1: Secret key loaded from environment, never hardcoded --------
app.secret_key = os.environ.get("APP_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "APP_SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

DB_PATH = "users.db"
UPLOAD_DIR = os.path.abspath("uploads")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)"
    )
    # --- Fix 2: Passwords are hashed, never stored in plaintext ---------
    hashed = generate_password_hash("admin123")
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', ?)",
        (hashed,),
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_PATH)
        # --- Fix 3: Parameterized query - eliminates SQL injection ------
        cursor = conn.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        )
        row = cursor.fetchone()
        conn.close()

        # --- Fix 2 (cont.): verify against the hash, not plaintext ------
        if row and check_password_hash(row[0], password):
            session["user"] = username
            return redirect("/welcome")
        return "Invalid credentials", 401

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """


@app.route("/welcome")
def welcome():
    name = request.args.get("name", session.get("user", "Guest"))
    # --- Fix 4: Output escaped before rendering - eliminates XSS --------
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=escape(name))


@app.route("/download")
def download():
    requested = request.args.get("file", "")
    # --- Fix 5: Filename sanitized and confined to UPLOAD_DIR -----------
    # secure_filename() strips path separators and traversal sequences;
    # send_from_directory() additionally refuses to escape the base dir.
    safe_name = secure_filename(requested)
    if not safe_name:
        return "Invalid filename", 400
    return send_from_directory(UPLOAD_DIR, safe_name)


@app.route("/load-preferences", methods=["POST"])
def load_preferences():
    # --- Fix 6: JSON replaces pickle - no arbitrary code execution ------
    prefs = request.get_json(silent=True)
    if prefs is None:
        return {"error": "Expected valid JSON body"}, 400
    return {"loaded": True, "preferences": prefs}


if __name__ == "__main__":
    init_db()
    # --- Fix 7: Debug disabled; bind to localhost unless explicitly ----
    #            configured otherwise via environment (e.g. behind a
    #            reverse proxy in a controlled deployment).
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    bind_host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(debug=debug_mode, host=bind_host)
