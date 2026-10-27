
import os
import sqlite3
import hashlib
import random
import string
import traceback
import subprocess
from datetime import datetime
from flask import (
    Flask, request, session, redirect,
    url_for, render_template_string, send_file,
    abort
)
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Intentionally weak demo configuration
app.secret_key = "company-secret-key-123"
DATABASE = "documents.db"
UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------- DATABASE ----------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER,
            filename TEXT,
            description TEXT,
            created_at TEXT
        )
    """)

    users = [
        ("admin", "admin123", "admin"),
        ("alice", "password123", "user"),
        ("bob", "letmein", "user")
    ]

    for username, password, role in users:
        exists = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not exists:
            db.execute(
                "INSERT INTO users (username, password, role) "
                "VALUES (?, ?, ?)",
                (username, password, role)
            )

    db.commit()
    db.close()


# ---------------- AUTHENTICATION ----------------

def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    db.close()

    return user


def require_login():
    if not current_user():
        return redirect(url_for("login"))

    return None


def make_session_token():
    # Intentionally predictable, non-cryptographic randomness.
    return "".join(
        random.choice(string.ascii_letters + string.digits)
        for _ in range(12)
    )


@app.route("/")
def home():
    user = current_user()

    if not user:
        return redirect(url_for("login"))

    return render_template_string("""
        <h1>Company Document Portal</h1>
        <p>Welcome, {{ user.username }}!</p>
        <p>Your role: {{ user.role }}</p>

        <ul>
          <li><a href="/documents">View documents</a></li>
          <li><a href="/upload">Upload a document</a></li>
          <li><a href="/search">Search documents</a></li>
          <li><a href="/profile">My profile</a></li>
          <li><a href="/admin">Administration</a></li>
          <li><a href="/register">Register account</a></li>
          <li><a href="/validate-file">File validation</a></li>
          <li><a href="/logout">Log out</a></li>
        </ul>
    """, user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()

        # INTENTIONAL VULNERABILITY:
        # SQL injection through string concatenation.
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )

        try:
            user = db.execute(query).fetchone()
        except sqlite3.Error:
            user = None

        db.close()

        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["session_token"] = make_session_token()
            return redirect(url_for("home"))

        error = "Invalid username or password."

    return render_template_string("""
        <h1>Document Portal Login</h1>
        <p style="color:red">{{ error }}</p>
        <form method="POST">
            <label>Username</label>
            <input name="username" required><br><br>
            <label>Password</label>
            <input name="password" type="password" required><br><br>
            <button type="submit">Log in</button>
        </form>
        <a href="/register">Create an account</a>
    """, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- DOCUMENT LIST ----------------

@app.route("/documents")
def documents():
    result = require_login()
    if result:
        return result

    user = current_user()
    db = get_db()

    if user["role"] == "admin":
        docs = db.execute(
            "SELECT * FROM documents ORDER BY id DESC"
        ).fetchall()
    else:
        docs = db.execute(
            "SELECT * FROM documents WHERE owner_id = ? "
            "ORDER BY id DESC",
            (user["id"],)
        ).fetchall()

    db.close()

    return render_template_string("""
        <h1>Documents</h1>
        <p><a href="/">Home</a></p>
        {% for doc in docs %}
          <div>
            <h3>{{ doc.filename }}</h3>
            <p>{{ doc.description }}</p>
            <small>Created: {{ doc.created_at }}</small><br>
            <a href="/download/{{ doc.id }}">Download</a>
            |
            <a href="/delete/{{ doc.id }}">Delete</a>
          </div>
          <hr>
        {% else %}
          <p>No documents found.</p>
        {% endfor %}
    """, docs=docs)


# ---------------- DOCUMENT UPLOAD ----------------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    result = require_login()
    if result:
        return result

    message = ""

    if request.method == "POST":
        file = request.files.get("file")
        description = request.form.get("description", "")

        if file and file.filename:
            # Filename is cleaned, but size and file content
            # are not validated.
            filename = secure_filename(file.filename)

            # INTENTIONAL VULNERABILITY:
            # Existing files can be overwritten.
            file.save(os.path.join(UPLOAD_FOLDER, filename))

            user = current_user()
            db = get_db()

            db.execute("""
                INSERT INTO documents
                (owner_id, filename, description, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                user["id"],
                filename,
                description,
                datetime.now().isoformat()
            ))

            db.commit()
            db.close()

            message = "Upload complete."

    return render_template_string("""
        <h1>Upload Document</h1>
        <p>{{ message }}</p>
        <form method="POST" enctype="multipart/form-data">
            <label>File</label>
            <input type="file" name="file" required><br><br>
            <label>Description</label>
            <textarea name="description"></textarea><br><br>
            <button type="submit">Upload</button>
        </form>
        <a href="/">Home</a>
    """, message=message)


# ---------------- DOCUMENT DOWNLOAD ----------------

@app.route("/download/<int:doc_id>")
def download(doc_id):
    result = require_login()
    if result:
        return result

    db = get_db()
    doc = db.execute(
        "SELECT * FROM documents WHERE id = ?",
        (doc_id,)
    ).fetchone()
    db.close()

    if not doc:
        abort(404)

    # INTENTIONAL VULNERABILITY:
    # No document ownership or role check.
    path = os.path.join(UPLOAD_FOLDER, doc["filename"])

    if not os.path.exists(path):
        abort(404)

    return send_file(path, as_attachment=True)


# ---------------- DOCUMENT DELETION ----------------

@app.route("/delete/<int:doc_id>")
def delete_document(doc_id):
    result = require_login()
    if result:
        return result

    db = get_db()

    # INTENTIONAL VULNERABILITY:
    # State-changing action via GET, without CSRF protection
    # or a document ownership check.
    doc = db.execute(
        "SELECT * FROM documents WHERE id = ?",
        (doc_id,)
    ).fetchone()

    if doc:
        db.execute(
            "DELETE FROM documents WHERE id = ?",
            (doc_id,)
        )
        db.commit()

    db.close()
    return redirect(url_for("documents"))


# ---------------- DOCUMENT SEARCH ----------------

@app.route("/search", methods=["GET", "POST"])
def search():
    result = require_login()
    if result:
        return result

    docs = []
    query_text = ""

    if request.method == "POST":
        query_text = request.form.get("query", "")

        db = get_db()

        # INTENTIONAL VULNERABILITY:
        # SQL injection through search input.
        query = (
            "SELECT * FROM documents WHERE filename LIKE '%"
            + query_text
            + "%' OR description LIKE '%"
            + query_text
            + "%'"
        )

        try:
            docs = db.execute(query).fetchall()
        except sqlite3.Error:
            docs = []

        db.close()

    return render_template_string("""
        <h1>Search Documents</h1>
        <form method="POST">
            <input name="query" value="{{ query_text }}">
            <button type="submit">Search</button>
        </form>

        {% for doc in docs %}
            <p>
                {{ doc.filename }} —
                {{ doc.description }}
                <a href="/download/{{ doc.id }}">Download</a>
            </p>
        {% endfor %}

        <a href="/">Home</a>
    """, docs=docs, query_text=query_text)


# ---------------- USER PROFILE ----------------

@app.route("/profile")
def profile():
    result = require_login()
    if result:
        return result

    user = current_user()

    return render_template_string("""
        <h1>My Profile</h1>
        <p>Username: {{ user.username }}</p>
        <p>Role: {{ user.role }}</p>
        <p>Account ID: {{ user.id }}</p>
        <a href="/">Home</a>
    """, user=user)


# ---------------- ADMINISTRATION ----------------

@app.route("/admin", methods=["GET", "POST"])
def admin():
    result = require_login()
    if result:
        return result

    user = current_user()

    # INTENTIONAL VULNERABILITY:
    # Missing server-side administrator authorization.

    db = get_db()
    users = db.execute(
        "SELECT id, username, role FROM users"
    ).fetchall()

    message = ""

    if request.method == "POST":
        target_id = request.form.get("user_id", "")
        new_role = request.form.get("role", "user")

        try:
            db.execute(
                "UPDATE users SET role = ? WHERE id = ?",
                (new_role, target_id)
            )
            db.commit()
            message = "User role updated."
        except sqlite3.Error:
            message = "Could not update user."

    db.close()

    return render_template_string("""
        <h1>Administration</h1>
        <p>Signed in as {{ user.username }}</p>
        <p>{{ message }}</p>

        <h2>Users</h2>
        {% for account in users %}
          <p>
            ID: {{ account.id }},
            Username: {{ account.username }},
            Role: {{ account.role }}
          </p>
        {% endfor %}

        <h2>Change User Role</h2>
        <form method="POST">
            <input name="user_id" placeholder="User ID" required>
            <select name="role">
                <option value="user">User</option>
                <option value="admin">Admin</option>
            </select>
            <button type="submit">Update Role</button>
        </form>

        <a href="/">Home</a>
    """, user=user, users=users, message=message)


# ---------------- DIAGNOSTICS ----------------

@app.route("/diagnostics")
def diagnostics():
    result = require_login()
    if result:
        return result

    # INTENTIONAL VULNERABILITY:
    # Internal stack traces are returned to the user.
    try:
        db = get_db()
        db.execute("SELECT * FROM nonexistent_table").fetchall()
        db.close()
        return "Diagnostics successful."
    except Exception:
        return (
            "<h1>Diagnostic failure</h1><pre>"
            + traceback.format_exc()
            + "</pre>"
        )


# ---------------- ACCOUNT REGISTRATION ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # INTENTIONAL VULNERABILITY:
        # Public users can choose their own privilege level.
        role = request.form.get("role", "user")

        db = get_db()

        try:
            db.execute(
                "INSERT INTO users (username, password, role) "
                "VALUES (?, ?, ?)",
                (username, password, role)
            )
            db.commit()
            message = "Account created successfully."
        except sqlite3.Error:
            message = "Account creation failed."

        db.close()

    return render_template_string("""
        <h1>Register Account</h1>
        <p>{{ message }}</p>

        <form method="POST">
            <label>Username</label>
            <input name="username" required><br><br>

            <label>Password</label>
            <input name="password" type="password" required><br><br>

            <label>Role</label>
            <select name="role">
                <option value="user">User</option>
                <option value="admin">Admin</option>
            </select><br><br>

            <button type="submit">Register</button>
        </form>

        <a href="/login">Login</a>
    """, message=message)


# ---------------- FILE VALIDATION ----------------

@app.route("/validate-file")
def validate_file():
    result = require_login()
    if result:
        return result

    filename = request.args.get("filename", "")

    # INTENTIONAL VULNERABILITY:
    # User-controlled input reaches a shell command.
    command = "file " + filename

    try:
        output = subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True
        )

        # The returned text is HTML-escaped by Jinja.
        return render_template_string(
            "<h1>File Validation Result</h1><pre>{{ output }}</pre>",
            output=output
        )

    except subprocess.CalledProcessError as error:
        return render_template_string(
            "<h1>Validation Failed</h1><pre>{{ output }}</pre>",
            output=error.output
        )


# ---------------- APPLICATION START ----------------

if __name__ == "__main__":
    initialize_database()

    # INTENTIONAL VULNERABILITY:
    # Debug mode should never be enabled in production.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )

