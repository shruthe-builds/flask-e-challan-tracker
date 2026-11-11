import hashlib
import hmac
import io
import math
import os
import re
import secrets
import smtplib
from datetime import date
from email.message import EmailMessage
from functools import wraps

import qrcode
from flask import (Flask, request, redirect, url_for, session,
                   send_file, render_template, flash, abort)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jinja2 import DictLoader
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

# Configuration comes from environment variables. The defaults are for a quick
# local trial only: set SECRET_KEY (and ideally REGISTRATION_CODE) for anything real.
DEFAULT_SECRET_KEY = "dev-only-change-me"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", DEFAULT_SECRET_KEY)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///violations.db")
db = SQLAlchemy(app)

# If set, people must enter this code to create an officer account.
REGISTRATION_CODE = os.environ.get("REGISTRATION_CODE", "")
RESET_MAX_AGE = 30 * 60   # password reset links stay valid for 30 minutes
# Address encoded in QR codes. Leave empty to use the address the page was opened with.
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")

MAX_LEN = {"vehicle_number": 20, "violation_type": 50, "location": 100}


class Violation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_number = db.Column(db.String(20), nullable=False)
    violation_type = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    fine = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(10), default="Unpaid")


class User(db.Model):
    __tablename__ = "officers"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)


# Used so a login attempt takes the same time whether or not the account exists.
DUMMY_HASH = generate_password_hash("not-a-real-password")

with app.app_context():
    db.create_all()


# ---------- Templates (inline so it's one file) ----------
TEMPLATES = {
    "base.html": """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Traffic Violation Logger</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body class="bg-light">
<nav class="navbar navbar-dark bg-dark mb-4"><div class="container">
  <a class="navbar-brand" href="/">🚦 Traffic Violation Logger</a>
  <div>
    <a class="btn btn-outline-light btn-sm" href="/">History</a>
    <a class="btn btn-outline-light btn-sm" href="/add">Add Violation</a>
    {% if session.get('user') %}<span class="text-light small mx-2">{{ session.get('user') }}</span>
    <a class="btn btn-warning btn-sm" href="/logout">Logout</a>
    {% else %}<a class="btn btn-success btn-sm" href="/login">Officer Login</a>
    <a class="btn btn-primary btn-sm" href="/register">Sign Up</a>{% endif %}
  </div></div></nav>
<div class="container">
  {% for m in get_flashed_messages() %}<div class="alert alert-info">{{ m }}</div>{% endfor %}
  {% block body %}{% endblock %}
</div></body></html>
""",
    "index.html": """
{% extends 'base.html' %}{% block body %}
<form class="row g-2 mb-3" method="get">
  <div class="col-md-3"><input class="form-control" name="vehicle" placeholder="Vehicle No." value="{{ request.args.get('vehicle','') }}"></div>
  <div class="col-md-3"><input class="form-control" name="vtype" placeholder="Violation type" value="{{ request.args.get('vtype','') }}"></div>
  <div class="col-md-2"><input type="date" class="form-control" name="date" value="{{ request.args.get('date','') }}"></div>
  <div class="col-md-2"><select class="form-select" name="status">
    <option value="">Any status</option>
    <option {% if request.args.get('status')=='Paid' %}selected{% endif %}>Paid</option>
    <option {% if request.args.get('status')=='Unpaid' %}selected{% endif %}>Unpaid</option></select></div>
  <div class="col-md-2"><button class="btn btn-primary w-100">Search</button></div>
</form>
<table class="table table-bordered bg-white">
<tr><th>ID</th><th>Vehicle</th><th>Type</th><th>Location</th><th>Date</th><th>Fine (₹)</th><th>Status</th><th>Actions</th></tr>
{% for v in violations %}
<tr><td>{{ v.id }}</td><td>{{ v.vehicle_number }}</td><td>{{ v.violation_type }}</td>
<td>{{ v.location }}</td><td>{{ v.date }}</td><td>{{ v.fine }}</td>
<td><span class="badge {{ 'bg-success' if v.status=='Paid' else 'bg-danger' }}">{{ v.status }}</span></td>
<td><a class="btn btn-sm btn-outline-dark" href="/challan/{{ v.id }}">Challan</a>
{% if v.status=='Unpaid' and session.get('user') %}
<form method="post" action="/pay/{{ v.id }}" class="d-inline"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn btn-sm btn-success">Mark Paid</button></form>
{% endif %}</td></tr>
{% else %}<tr><td colspan="8" class="text-center">No records found</td></tr>
{% endfor %}</table>
{% endblock %}
""",
    "add.html": """
{% extends 'base.html' %}{% block body %}
<div class="card p-4 col-md-6 mx-auto"><h4>Add Violation</h4>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input class="form-control mb-2" name="vehicle_number" placeholder="Vehicle Number" maxlength="20" required>
  <input class="form-control mb-2" name="violation_type" placeholder="Violation Type (No Helmet, Overspeeding...)" maxlength="50" required>
  <input class="form-control mb-2" name="location" placeholder="Location" maxlength="100" required>
  <input type="date" class="form-control mb-2" name="date" value="{{ today }}" required>
  <input type="number" step="0.01" min="0.01" class="form-control mb-3" name="fine" placeholder="Fine Amount" required>
  <button class="btn btn-primary">Save</button>
</form></div>{% endblock %}
""",
    "login.html": """
{% extends 'base.html' %}{% block body %}
<div class="card p-4 col-md-4 mx-auto"><h4>Officer Login</h4>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input class="form-control mb-2" name="username" placeholder="Username or email" required autocomplete="username">
  <input type="password" class="form-control mb-2" name="password" placeholder="Password" required autocomplete="current-password">
  <div class="mb-3 small"><a href="/forgot">Forgot password?</a></div>
  <button class="btn btn-primary">Login</button>
</form>
<div class="mt-3 small">New officer? <a href="/register">Create an account</a></div></div>{% endblock %}
""",
    "register.html": """
{% extends 'base.html' %}{% block body %}
<div class="card p-4 col-md-5 mx-auto"><h4>Create Officer Account</h4>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input class="form-control mb-2" name="username" placeholder="Username (3-30: letters, numbers, . _ -)" maxlength="30" value="{{ form.get('username', '') }}" required autocomplete="username">
  <input type="email" class="form-control mb-2" name="email" placeholder="Email" maxlength="120" value="{{ form.get('email', '') }}" required autocomplete="email">
  <input type="password" class="form-control mb-2" name="password" placeholder="Password (at least 8 characters)" minlength="8" required autocomplete="new-password">
  <input type="password" class="form-control mb-2" name="confirm" placeholder="Confirm password" minlength="8" required autocomplete="new-password">
  {% if needs_code %}<input class="form-control mb-2" name="code" placeholder="Officer registration code" required>{% endif %}
  <button class="btn btn-primary mt-2">Create account</button>
</form>
<div class="mt-3 small">Already have an account? <a href="/login">Log in</a></div></div>{% endblock %}
""",
    "forgot.html": """
{% extends 'base.html' %}{% block body %}
<div class="card p-4 col-md-4 mx-auto"><h4>Forgot Password</h4>
<p class="small text-muted">Enter the email you registered with and we will send you a link to reset your password.</p>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input type="email" class="form-control mb-3" name="email" placeholder="Email" maxlength="120" required autocomplete="email">
  <button class="btn btn-primary">Send reset link</button>
</form>
<div class="mt-3 small"><a href="/login">Back to login</a></div></div>{% endblock %}
""",
    "reset.html": """
{% extends 'base.html' %}{% block body %}
<div class="card p-4 col-md-4 mx-auto"><h4>Choose a New Password</h4>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input type="password" class="form-control mb-2" name="password" placeholder="New password (at least 8 characters)" minlength="8" required autocomplete="new-password">
  <input type="password" class="form-control mb-3" name="confirm" placeholder="Confirm new password" minlength="8" required autocomplete="new-password">
  <button class="btn btn-primary">Update password</button>
</form></div>{% endblock %}
""",
    "challan.html": """
{% extends 'base.html' %}{% block body %}
<div class="card p-4 col-md-6 mx-auto text-center"><h4>Digital Challan #{{ v.id }}</h4>
<p><b>Vehicle:</b> {{ v.vehicle_number }}<br><b>Violation:</b> {{ v.violation_type }}<br>
<b>Location:</b> {{ v.location }}<br><b>Date:</b> {{ v.date }}<br>
<b>Fine:</b> ₹{{ v.fine }}<br><b>Status:</b> {{ v.status }}</p>
<img src="/qr/{{ v.id }}.png" width="200" class="mx-auto">
<small class="text-muted">Scan to check payment status</small></div>{% endblock %}
""",
    "status.html": """
{% extends 'base.html' %}{% block body %}
<div class="card p-4 col-md-6 mx-auto"><h4>Fine Status</h4>
<p><b>Vehicle:</b> {{ v.vehicle_number }}<br><b>Violation:</b> {{ v.violation_type }}<br>
<b>Location:</b> {{ v.location }}<br><b>Date:</b> {{ v.date }}<br><b>Fine:</b> ₹{{ v.fine }}</p>
<h3><span class="badge {{ 'bg-success' if v.status=='Paid' else 'bg-danger' }}">{{ v.status }}</span></h3>
</div>{% endblock %}
""",
}
app.jinja_loader = DictLoader(TEMPLATES)


# ---------- Security & input helpers ----------
def csrf_token():
    """Per-session token that every POST form must send back."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}


@app.before_request
def protect_from_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


def parse_date(text):
    """ISO date string -> date, or None if it is not a valid date."""
    try:
        return date.fromisoformat(text)
    except (TypeError, ValueError):
        return None


def parse_fine(text):
    """Positive, finite number -> float, otherwise None."""
    try:
        fine = float(text)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(fine) or fine <= 0:
        return None
    return fine


USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


def validate_new_password(password, confirm):
    """Return an error message, or None if the password is acceptable."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 128:
        return "Password is too long (maximum 128 characters)."
    if password != confirm:
        return "Passwords do not match."
    return None


def validate_registration(username, email, password, confirm):
    """Return an error message, or None if the sign-up details are acceptable."""
    if not USERNAME_RE.match(username):
        return "Username must be 3-30 characters: letters, numbers, dot, underscore or dash."
    if len(email) > 120 or not EMAIL_RE.match(email):
        return "Enter a valid email address."
    return validate_new_password(password, confirm)


def _reset_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="password-reset")


def _fingerprint(user):
    # Changes whenever the password changes, so a reset link works only once.
    return hashlib.sha256(user.password_hash.encode()).hexdigest()[:16]


def make_reset_token(user):
    return _reset_serializer().dumps({"uid": user.id, "fp": _fingerprint(user)})


def user_from_reset_token(token):
    """Return the user a valid, unexpired, unused reset token belongs to, else None."""
    try:
        data = _reset_serializer().loads(token, max_age=RESET_MAX_AGE)
        user = db.session.get(User, data["uid"])
        fingerprint = data["fp"]
    except (BadSignature, KeyError, TypeError):
        return None
    if user is None or not hmac.compare_digest(fingerprint, _fingerprint(user)):
        return None
    return user


def send_email(to, subject, body):
    """Send through SMTP if SMTP_HOST is set, otherwise print it (local development)."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        print(f"\n[email not configured - printing instead]\nTo: {to}\nSubject: {subject}\n\n{body}\n")
        return
    smtp_user = os.environ.get("SMTP_USER", "")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("MAIL_FROM", smtp_user)
    msg["To"] = to
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=15) as server:
        server.starttls()
        if smtp_user:
            server.login(smtp_user, os.environ.get("SMTP_PASS", ""))
        server.send_message(msg)


# ---------- Auth ----------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("user"):
            flash("Please log in first.")
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter((User.username == ident) | (User.email == ident)).first()
        # Always run one hash check so timing does not reveal whether the account exists.
        password_ok = check_password_hash(user.password_hash if user else DUMMY_HASH, password)
        if user and password_ok:
            username = user.username
            session.clear()
            session["user"] = username
            return redirect(url_for("index"))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    needs_code = bool(REGISTRATION_CODE)
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        code = request.form.get("code", "")

        if needs_code and not hmac.compare_digest(code.encode(), REGISTRATION_CODE.encode()):
            error = "Invalid officer registration code."
        else:
            error = validate_registration(username, email, password, confirm)
        if not error and User.query.filter((User.username == username) | (User.email == email)).first():
            error = "That username or email is already registered."
        if not error:
            db.session.add(User(username=username, email=email,
                                password_hash=generate_password_hash(password)))
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                error = "That username or email is already registered."
        if error:
            flash(error)
            return render_template("register.html", needs_code=needs_code, form=request.form), 400

        session.clear()
        session["user"] = username
        flash("Account created. Welcome!")
        return redirect(url_for("index"))
    return render_template("register.html", needs_code=needs_code, form={})


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            base = BASE_URL or request.host_url.rstrip("/")
            link = base + url_for("reset_password", token=make_reset_token(user))
            body = ("We received a request to reset your Traffic Violation Logger password.\n\n"
                    f"Open this link within {RESET_MAX_AGE // 60} minutes to choose a new one:\n\n"
                    f"{link}\n\n"
                    "If you did not ask for this, you can ignore this email.")
            try:
                send_email(user.email, "Reset your password", body)
            except Exception:
                app.logger.exception("Could not send the password reset email")
        # Same message whether or not the email is registered, so it can't be used to probe accounts.
        flash("If that email is registered, a password reset link has been sent.")
        return redirect(url_for("login"))
    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = user_from_reset_token(token)
    if user is None:
        flash("That reset link is invalid or has expired. Please request a new one.")
        return redirect(url_for("forgot"))
    if request.method == "POST":
        password = request.form.get("password", "")
        error = validate_new_password(password, request.form.get("confirm", ""))
        if error:
            flash(error)
            return render_template("reset.html"), 400
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        session.clear()
        flash("Password updated. Please log in.")
        return redirect(url_for("login"))
    return render_template("reset.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------- Routes ----------
@app.route("/")
def index():
    q = Violation.query
    if request.args.get("vehicle"):
        q = q.filter(Violation.vehicle_number.ilike(f"%{request.args['vehicle']}%"))
    if request.args.get("vtype"):
        q = q.filter(Violation.violation_type.ilike(f"%{request.args['vtype']}%"))
    if request.args.get("status"):
        q = q.filter_by(status=request.args["status"])
    if request.args.get("date"):
        wanted = parse_date(request.args["date"])
        if wanted is None:
            flash("Invalid date filter ignored.")
        else:
            q = q.filter_by(date=wanted)
    return render_template("index.html", violations=q.order_by(Violation.id.desc()).all())


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        vehicle = request.form.get("vehicle_number", "").upper().strip()
        vtype = request.form.get("violation_type", "").strip()
        location = request.form.get("location", "").strip()
        vdate = parse_date(request.form.get("date"))
        fine = parse_fine(request.form.get("fine"))

        error = None
        if not (vehicle and vtype and location):
            error = "All fields are required."
        elif (len(vehicle) > MAX_LEN["vehicle_number"]
              or len(vtype) > MAX_LEN["violation_type"]
              or len(location) > MAX_LEN["location"]):
            error = "One of the fields is too long."
        elif vdate is None:
            error = "Enter a valid date."
        elif fine is None:
            error = "Fine must be a positive number."
        if error:
            flash(error)
            return render_template("add.html", today=date.today().isoformat()), 400

        v = Violation(vehicle_number=vehicle, violation_type=vtype,
                      location=location, date=vdate, fine=fine)
        db.session.add(v)
        db.session.commit()
        return redirect(url_for("challan", vid=v.id))
    return render_template("add.html", today=date.today().isoformat())


@app.route("/pay/<int:vid>", methods=["POST"])
@login_required
def pay(vid):
    v = db.get_or_404(Violation, vid)
    v.status = "Paid"
    db.session.commit()
    flash(f"Challan #{vid} marked as Paid")
    return redirect(request.referrer or url_for("index"))


@app.route("/challan/<int:vid>")
def challan(vid):
    return render_template("challan.html", v=db.get_or_404(Violation, vid))


@app.route("/status/<int:vid>")
def status(vid):
    return render_template("status.html", v=db.get_or_404(Violation, vid))


@app.route("/qr/<int:vid>.png")
def qr(vid):
    db.get_or_404(Violation, vid)
    base = BASE_URL or request.host_url.rstrip("/")
    url = base + url_for("status", vid=vid)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


if __name__ == "__main__":
    if app.config["SECRET_KEY"] == DEFAULT_SECRET_KEY:
        print("WARNING: using the default SECRET_KEY. Set SECRET_KEY before using this for real.")
    if not REGISTRATION_CODE:
        print("NOTE: REGISTRATION_CODE is not set, so anyone who can reach this app can create an officer account.")
    if not os.environ.get("SMTP_HOST"):
        print("NOTE: SMTP_HOST is not set, so password reset links are printed here instead of emailed.")
    # host 0.0.0.0 so a phone on the same Wi-Fi can scan the QR
    app.run(host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes"))
