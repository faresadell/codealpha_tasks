"""
UserPortal - Sample Application (PRE-AUDIT VERSION)
=====================================================
CodeAlpha Cyber Security Internship - Task 3: Secure Coding Review

This is a small Flask web app used as the AUDIT TARGET for this task.
It intentionally contains common real-world vulnerabilities so they can be
identified, documented, and remediated as part of a professional secure
code review. See SECURITY_REVIEW.md for the full findings report and
app_after/ for the remediated version.

DO NOT deploy this version - it is for training/demonstration only.
"""

import sqlite3
import pickle
import os
from flask import Flask, request, redirect, session, render_template_string, send_file

app = Flask(__name__)

# --- Finding 1: Hardcoded secret key -----------------------------------
app.secret_key = "dev12345"

DB_PATH = "users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    # --- Finding 2: Plaintext password storage --------------------------
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_PATH)
        # --- Finding 3: SQL Injection (string concatenation) ------------
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor = conn.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect("/welcome")
        return "Invalid credentials"

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
    # --- Finding 4: Reflected XSS (unescaped user input in HTML) --------
    return render_template_string(f"<h1>Welcome, {name}!</h1>")


@app.route("/download")
def download():
    filename = request.args.get("file")
    # --- Finding 5: Path Traversal (unsanitized file path) --------------
    filepath = os.path.join("uploads", filename)
    return send_file(filepath)


@app.route("/load-preferences", methods=["POST"])
def load_preferences():
    # --- Finding 6: Insecure Deserialization (pickle on user input) -----
    raw = request.get_data()
    prefs = pickle.loads(raw)
    return {"loaded": True, "preferences": str(prefs)}


if __name__ == "__main__":
    init_db()
    # --- Finding 7: Debug mode enabled in a way that could reach prod ---
    app.run(debug=True, host="0.0.0.0")
