"""
Single-file Python web application implementing:
- User registration, login, logout
- Password hashing (Werkzeug)
- User roles: admin and user (with simple permission checks)
- Password reset via email (SMTP if configured) or printed to console for development
- Simple "posts" resource to demonstrate permissions (create/edit/delete by author or admin)

Requirements:
pip install flask flask_sqlalchemy flask_login itsdangerous

Run:
python app.py
Visit http://127.0.0.1:5000/
"""

import os
import smtplib
from email.message import EmailMessage
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, render_template_string, flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ---------- Configuration ----------
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-key-change-me")
DATABASE_FILE = os.environ.get("DATABASE_FILE", "sqlite:///app.db")
SMTP_HOST = os.environ.get("SMTP_HOST", "")  # e.g., smtp.gmail.com
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587")) if os.environ.get("SMTP_PORT") else None
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@example.com")
RESET_TOKEN_SALT = "password-reset-salt"
RESET_TOKEN_EXP_SECONDS = 3600  # 1 hour

# ---------- App & Extensions ----------
app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_FILE
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# ---------- Models ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == "admin"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(220), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author = db.relationship("User", backref="posts")

# ---------- Helpers ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return func(*args, **kwargs)
    return wrapper

def send_reset_email(to_email, token):
    reset_link = url_for("password_reset_confirm", token=token, _external=True)
    subject = "Password reset for your account"
    body = f"Use this link to reset your password (valid for {RESET_TOKEN_EXP_SECONDS//60} minutes):\n\n{reset_link}\n\nIf you didn't request this, ignore."
    # If SMTP configured, try to send; otherwise print to console
    if SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS:
        try:
            msg = EmailMessage()
            msg.set_content(body)
            msg["Subject"] = subject
            msg["From"] = FROM_EMAIL
            msg["To"] = to_email
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
            print("Password reset email sent via SMTP.")
        except Exception as e:
            print("Failed to send email via SMTP, printing to console instead.", e)
            print("----- PASSWORD RESET LINK -----")
            print(body)
            print("----- END -----")
    else:
        print("----- PASSWORD RESET LINK (console) -----")
        print(body)
        print("----- END -----")

def generate_reset_token(email):
    return serializer.dumps(email, salt=RESET_TOKEN_SALT)

def verify_reset_token(token, max_age=RESET_TOKEN_EXP_SECONDS):
    try:
        email = serializer.loads(token, salt=RESET_TOKEN_SALT, max_age=max_age)
        return email
    except SignatureExpired:
        return None
    except BadSignature:
        return None

# ---------- Routes & Views (templates inlined via render_template_string) ----------
base_tpl = """
<!doctype html>
<title>Auth App</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/mini.css/3.0.1/mini-default.min.css">
<nav>
  <a href="{{ url_for('index') }}">Home</a> |
  <a href="{{ url_for('post_list') }}">Posts</a> |
  {% if current_user.is_authenticated %}
    Hello <strong>{{ current_user.username }}</strong> ({{ current_user.role }}) |
    <a href="{{ url_for('profile') }}">Profile</a> |
    <a href="{{ url_for('logout') }}">Logout</a>
  {% else %}
    <a href="{{ url_for('login') }}">Login</a> |
    <a href="{{ url_for('register') }}">Register</a>
  {% endif %}
</nav>
<main class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <section>
      {% for category, msg in messages %}
        <div class="card {{ 'success' if category=='success' else 'error' }}" style="padding:10px;margin:8px 0;">{{ msg }}</div>
      {% endfor %}
      </section>
    {% endif %}
  {% endwith %}
  {% block body %}{% endblock %}
</main>
"""

@app.route("/")
def index():
    return render_template_string(
        base_tpl + """
        {% block body %}
        <h2>Welcome</h2>
        <p>Single-file auth app demo. Register, login, create posts. Password reset link is printed to console unless SMTP is configured.</p>
        {% endblock %}
        """
    )

# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if not username or not email or not password:
            flash("All fields are required.", "error")
        elif User.query.filter((User.username==username)|(User.email==email)).first():
            flash("User with that username or email already exists.", "error")
        else:
            u = User(username=username, email=email, role=role)
            u.set_password(password)
            if role == "admin":
                # In small demo, allow creating admin users via form; in production protect this.
                u.role = "admin"
            db.session.add(u)
            db.session.commit()
            login_user(u)
            flash("Registered and logged in.", "success")
            return redirect(url_for("index"))
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Register</h2>
    <form method="post">
      <label>Username <input name="username" required></label>
      <label>Email <input name="email" type="email" required></label>
      <label>Password <input name="password" type="password" required></label>
      <label>Role
        <select name="role">
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </label>
      <button type="submit">Register</button>
    </form>
    {% endblock %}
    """)

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username_or_email = request.form.get("username_or_email", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter((User.username==username_or_email)|(User.email==username_or_email)).first()
        if not user or not user.check_password(password):
            flash("Invalid credentials.", "error")
        else:
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Login</h2>
    <form method="post">
      <label>Username or Email <input name="username_or_email" required></label>
      <label>Password <input name="password" type="password" required></label>
      <button type="submit">Login</button>
    </form>
    <p><a href="{{ url_for('password_reset_request') }}">Forgot password?</a></p>
    {% endblock %}
    """)

# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("index"))

# Profile
@app.route("/profile")
@login_required
def profile():
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Profile</h2>
    <p>Username: {{ current_user.username }}</p>
    <p>Email: {{ current_user.email }}</p>
    <p>Role: {{ current_user.role }}</p>
    {% endblock %}
    """)

# Password reset: request
@app.route("/password-reset", methods=["GET", "POST"])
def password_reset_request():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Please provide an email.", "error")
        else:
            user = User.query.filter_by(email=email).first()
            if user:
                token = generate_reset_token(user.email)
                send_reset_email(user.email, token)
                flash("If that email exists in our system, a reset link was sent (or printed to console).", "success")
            else:
                # Don't reveal existence
                flash("If that email exists in our system, a reset link was sent (or printed to console).", "success")
            return redirect(url_for("index"))
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Request Password Reset</h2>
    <form method="post">
      <label>Email <input name="email" type="email" required></label>
      <button type="submit">Send Reset Link</button>
    </form>
    {% endblock %}
    """)

# Password reset: confirm token & set new password
@app.route("/password-reset/<token>", methods=["GET", "POST"])
def password_reset_confirm(token):
    email = verify_reset_token(token)
    if not email:
        flash("This reset link is invalid or has expired.", "error")
        return redirect(url_for("password_reset_request"))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("index"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        if not pw or pw != pw2:
            flash("Passwords must match and be non-empty.", "error")
        else:
            user.set_password(pw)
            db.session.commit()
            flash("Password reset successfully. Please login.", "success")
            return redirect(url_for("login"))
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Reset Password for {{ email }}</h2>
    <form method="post">
      <label>New Password <input name="password" type="password" required></label>
      <label>Confirm Password <input name="password2" type="password" required></label>
      <button type="submit">Reset Password</button>
    </form>
    {% endblock %}
    """, email=email)

# ---------- Simple Posts to show permissions ----------
@app.route("/posts")
def post_list():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Posts</h2>
    {% if current_user.is_authenticated %}<p><a href="{{ url_for('post_create') }}">Create new post</a></p>{% endif %}
    <ul>
      {% for p in posts %}
        <li><a href="{{ url_for('post_detail', post_id=p.id) }}">{{ p.title }}</a> by {{ p.author.username }} ({{ p.created_at.strftime('%Y-%m-%d %H:%M') }})</li>
      {% else %}<li>No posts yet.</li>{% endfor %}
    </ul>
    {% endblock %}
    """, posts=posts)

@app.route("/posts/<int:post_id>")
def post_detail(post_id):
    p = Post.query.get_or_404(post_id)
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>{{ p.title }}</h2>
    <p><em>by {{ p.author.username }} on {{ p.created_at.strftime('%Y-%m-%d %H:%M') }}</em></p>
    <div style="white-space:pre-wrap;">{{ p.body }}</div>
    {% if current_user.is_authenticated and (current_user.id==p.author_id or current_user.is_admin()) %}
      <p><a href="{{ url_for('post_edit', post_id=p.id) }}">Edit</a> |
         <a href="{{ url_for('post_delete', post_id=p.id) }}">Delete</a></p>
    {% endif %}
    <p><a href="{{ url_for('post_list') }}">Back to posts</a></p>
    {% endblock %}
    """, p=p)

@app.route("/posts/new", methods=["GET", "POST"])
@login_required
def post_create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title or not body:
            flash("Title and body required.", "error")
        else:
            post = Post(title=title, body=body, author=current_user)
            db.session.add(post)
            db.session.commit()
            flash("Post created.", "success")
            return redirect(url_for("post_detail", post_id=post.id))
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Create Post</h2>
    <form method="post">
      <label>Title <input name="title" required></label>
      <label>Body <textarea name="body" rows="8" required></textarea></label>
      <button type="submit">Create</button>
    </form>
    {% endblock %}
    """)

@app.route("/posts/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def post_edit(post_id):
    p = Post.query.get_or_404(post_id)
    if not (current_user.id == p.author_id or current_user.is_admin()):
        abort(403)
    if request.method == "POST":
        p.title = request.form.get("title", "").strip()
        p.body = request.form.get("body", "").strip()
        db.session.commit()
        flash("Post updated.", "success")
        return redirect(url_for("post_detail", post_id=p.id))
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Edit Post</h2>
    <form method="post">
      <label>Title <input name="title" value="{{ p.title|e }}" required></label>
      <label>Body <textarea name="body" rows="8" required>{{ p.body|e }}</textarea></label>
      <button type="submit">Save</button>
    </form>
    {% endblock %}
    """, p=p)

@app.route("/posts/<int:post_id>/delete", methods=["GET", "POST"])
@login_required
def post_delete(post_id):
    p = Post.query.get_or_404(post_id)
    if not (current_user.id == p.author_id or current_user.is_admin()):
        abort(403)
    if request.method == "POST":
        db.session.delete(p)
        db.session.commit()
        flash("Post deleted.", "success")
        return redirect(url_for("post_list"))
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Delete Post</h2>
    <p>Are you sure you want to delete "{{ p.title }}"?</p>
    <form method="post"><button type="submit">Confirm Delete</button></form>
    <p><a href="{{ url_for('post_detail', post_id=p.id) }}">Cancel</a></p>
    {% endblock %}
    """, p=p)

# Admin-only example
@app.route("/admin-only")
@admin_required
def admin_only():
    users = User.query.all()
    return render_template_string(base_tpl + """
    {% block body %}
    <h2>Admin area</h2>
    <p>List of users:</p>
    <ul>
      {% for u in users %}<li>{{ u.username }} ({{ u.email }}) - role: {{ u.role }}</li>{% endfor %}
    </ul>
    {% endblock %}
    """, users=users)

# ---------- Initialize DB and run ----------
def ensure_db():
    db.create_all()
    # Create an initial admin user if none exists (convenience)
    if not User.query.filter_by(role="admin").first():
        admin_user = User(username="admin", email="admin@example.com", role="admin")
        admin_user.set_password("adminpass")
        db.session.add(admin_user)
        db.session.commit()
        print("Created default admin: admin / adminpass (change immediately)")

if __name__ == "__main__":
    ensure_db()
    app.run(debug=True)
  
