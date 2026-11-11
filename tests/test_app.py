import os
import re
import sys

# Configure the app for testing *before* importing it.
os.environ["DATABASE_URL"] = "sqlite://"          # in-memory database
os.environ["SECRET_KEY"] = "test-secret"
os.environ.pop("SMTP_HOST", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import app as appmod  # noqa: E402
from app import User, Violation, app, db  # noqa: E402

TOKEN = "test-token"
PASSWORD = "test-pass-123"


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    with app.app_context():
        db.drop_all()
        db.create_all()
    with app.test_client() as c:
        yield c


def post(client, url, data=None):
    """POST with a valid CSRF token (login/logout/register reset the session's token)."""
    with client.session_transaction() as s:
        s["_csrf"] = TOKEN
    return client.post(url, data={**(data or {}), "csrf_token": TOKEN})


def register(client, **overrides):
    data = {"username": "officer", "email": "officer@example.com",
            "password": PASSWORD, "confirm": PASSWORD}
    data.update(overrides)
    return post(client, "/register", data)


def login(client, ident="officer", password=PASSWORD):
    return post(client, "/login", {"username": ident, "password": password})


def add_violation(client, **overrides):
    data = {"vehicle_number": "tn4320", "violation_type": "Overspeeding",
            "location": "Karur", "date": "2026-10-04", "fine": "1200"}
    data.update(overrides)
    return post(client, "/add", data)


def get_violation(vid):
    with app.app_context():
        return db.session.get(Violation, vid)


def find_user(username):
    with app.app_context():
        return User.query.filter_by(username=username).first()


def session_user(client):
    with client.session_transaction() as s:
        return s.get("user")


@pytest.fixture
def outbox(monkeypatch):
    """Capture emails instead of sending them."""
    sent = []
    monkeypatch.setattr(appmod, "send_email", lambda to, subject, body: sent.append((to, subject, body)))
    return sent


def reset_token_from(outbox):
    return re.search(r"/reset/(\S+)", outbox[-1][2]).group(1)


# ---------- accounts ----------

def test_register_creates_account_hashes_password_and_logs_in(client):
    resp = register(client)
    assert resp.status_code == 302
    assert session_user(client) == "officer"
    user = find_user("officer")
    assert user.email == "officer@example.com"
    assert user.password_hash != PASSWORD
    assert user.password_hash.startswith(("scrypt:", "pbkdf2:"))


@pytest.mark.parametrize("overrides", [
    {"username": "ab"},
    {"username": "bad name!"},
    {"email": "not-an-email"},
    {"password": "short", "confirm": "short"},
    {"confirm": "different-123"},
])
def test_register_rejects_bad_input(client, overrides):
    resp = register(client, **overrides)
    assert resp.status_code == 400
    assert find_user("officer") is None


def test_duplicate_username_or_email_rejected(client):
    register(client)
    client.get("/logout")
    assert register(client, email="other@example.com").status_code == 400
    assert register(client, username="other").status_code == 400
    assert find_user("other") is None


def test_registration_code_required_when_configured(client, monkeypatch):
    monkeypatch.setattr(appmod, "REGISTRATION_CODE", "letmein")
    assert register(client).status_code == 400
    assert find_user("officer") is None
    assert register(client, code="wrong").status_code == 400
    assert register(client, code="letmein").status_code == 302
    assert find_user("officer") is not None


def test_login_by_username_or_email(client):
    register(client)
    client.get("/logout")
    assert session_user(client) is None

    assert login(client, "officer").status_code == 302
    assert session_user(client) == "officer"
    client.get("/logout")

    assert login(client, "Officer@Example.com").status_code == 302
    assert session_user(client) == "officer"


def test_login_with_wrong_password_or_unknown_user_rejected(client):
    register(client)
    client.get("/logout")
    for ident, password in [("officer", "wrong-password"), ("nobody", PASSWORD)]:
        resp = login(client, ident, password)
        assert resp.status_code == 200
        assert b"Invalid credentials" in resp.data
        assert session_user(client) is None


def test_logout_clears_session(client):
    register(client)
    client.get("/logout")
    assert session_user(client) is None


def test_login_page_links_to_signup_and_forgot_password(client):
    body = client.get("/login").data
    assert b'href="/register"' in body
    assert b'href="/forgot"' in body


# ---------- forgot / reset password ----------

def test_forgot_password_for_unknown_email_sends_nothing(client, outbox):
    resp = post(client, "/forgot", {"email": "nobody@example.com"})
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]
    assert outbox == []


def test_full_password_reset_flow(client, outbox):
    register(client)
    client.get("/logout")

    resp = post(client, "/forgot", {"email": "Officer@Example.com"})
    assert resp.status_code == 302
    assert len(outbox) == 1 and outbox[0][0] == "officer@example.com"
    token = reset_token_from(outbox)

    assert b"Choose a New Password" in client.get(f"/reset/{token}").data
    assert post(client, f"/reset/{token}", {"password": "new-pass-456", "confirm": "nope"}).status_code == 400
    assert post(client, f"/reset/{token}", {"password": "short", "confirm": "short"}).status_code == 400

    resp = post(client, f"/reset/{token}", {"password": "new-pass-456", "confirm": "new-pass-456"})
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]

    assert login(client, "officer", PASSWORD).status_code == 200           # old password no longer works
    assert session_user(client) is None
    assert login(client, "officer", "new-pass-456").status_code == 302     # new one does
    assert session_user(client) == "officer"

    client.get("/logout")
    resp = client.get(f"/reset/{token}")                                   # link cannot be used twice
    assert resp.status_code == 302 and "/forgot" in resp.headers["Location"]


def test_reset_with_invalid_token_redirects_to_forgot(client):
    resp = client.get("/reset/not-a-real-token")
    assert resp.status_code == 302 and "/forgot" in resp.headers["Location"]


def test_expired_reset_link_is_rejected(client, outbox, monkeypatch):
    register(client)
    client.get("/logout")
    post(client, "/forgot", {"email": "officer@example.com"})
    token = reset_token_from(outbox)
    monkeypatch.setattr(appmod, "RESET_MAX_AGE", -1)
    resp = client.get(f"/reset/{token}")
    assert resp.status_code == 302 and "/forgot" in resp.headers["Location"]


# ---------- violations ----------

def test_history_page_loads_empty(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"No records found" in resp.data


def test_add_requires_login(client):
    resp = client.get("/add")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_post_without_csrf_token_is_rejected(client):
    register(client)
    with client.session_transaction() as s:
        s["_csrf"] = TOKEN
    resp = client.post("/add", data={"vehicle_number": "TN1"})
    assert resp.status_code == 400


def test_add_violation_creates_record_and_uppercases_vehicle(client):
    register(client)
    resp = add_violation(client)
    assert resp.status_code == 302
    assert "/challan/1" in resp.headers["Location"]
    v = get_violation(1)
    assert v.vehicle_number == "TN4320"
    assert v.fine == 1200.0
    assert v.status == "Unpaid"


@pytest.mark.parametrize("overrides", [
    {"fine": "-5"}, {"fine": "0"}, {"fine": "abc"}, {"fine": "nan"},
    {"date": "not-a-date"}, {"vehicle_number": "X" * 21}, {"location": "  "},
])
def test_add_violation_rejects_bad_input(client, overrides):
    register(client)
    resp = add_violation(client, **overrides)
    assert resp.status_code == 400
    assert get_violation(1) is None


def test_invalid_search_date_does_not_crash(client):
    assert client.get("/?date=not-a-date").status_code == 200


def test_search_filters(client):
    register(client)
    add_violation(client, vehicle_number="TN0001")
    add_violation(client, vehicle_number="KA0002")
    resp = client.get("/?vehicle=tn0001")
    assert b"TN0001" in resp.data
    assert b"KA0002" not in resp.data
    resp = client.get("/?status=Paid")
    assert b"No records found" in resp.data


def test_mark_paid_requires_login_and_updates_status(client):
    register(client)
    add_violation(client)
    client.get("/logout")

    resp = post(client, "/pay/1")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]
    assert get_violation(1).status == "Unpaid"

    login(client)
    resp = post(client, "/pay/1")
    assert resp.status_code == 302
    assert get_violation(1).status == "Paid"


def test_challan_and_status_pages(client):
    register(client)
    add_violation(client)
    assert b"TN4320" in client.get("/challan/1").data
    assert b"Unpaid" in client.get("/status/1").data


def test_unknown_challan_is_404(client):
    assert client.get("/challan/999").status_code == 404
    assert client.get("/status/999").status_code == 404
    assert client.get("/qr/999.png").status_code == 404


def test_qr_code_is_a_png(client):
    register(client)
    add_violation(client)
    resp = client.get("/qr/1.png")
    assert resp.status_code == 200
    assert resp.mimetype == "image/png"
    assert resp.data.startswith(b"\x89PNG")
