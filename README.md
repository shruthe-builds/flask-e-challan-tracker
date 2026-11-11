# Traffic Violation Logger

A Flask web app for logging traffic violations and issuing **digital challans**. An officer records a violation, the app generates a challan page with a **QR code**, and scanning the QR code opens a public page showing the fine and whether it has been paid.

## Features
- **Officer accounts:** sign up, log in with username or email, and log out
- **Forgot password:** emailed reset link that expires after 30 minutes and works only once
- Passwords are stored as salted hashes, never as plain text
- Add a violation: vehicle number, violation type, location, date and fine
- Digital challan page for every violation, with a QR code
- Public status page (opened by scanning the QR code) showing Paid / Unpaid
- History page with search by vehicle number, violation type, date and status
- Officers can mark a challan as **Paid**
- Input validation and CSRF protection on every form

## Tech stack
Python 3.9+ · Flask · Flask-SQLAlchemy · SQLite · Werkzeug password hashing · itsdangerous (signed reset links) · qrcode (with Pillow) · Jinja2 · Bootstrap 5 (loaded from a CDN) · pytest · GitHub Actions

## Setup
```bash
git clone https://github.com/<your-username>/traffic-violation-logger.git
cd traffic-violation-logger
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000/, click **Sign Up**, and create your officer account. The database (`instance/violations.db`) is created automatically on first run.

## Accounts and password reset
- **Sign up** at `/register` with a username, email and password (at least 8 characters).
- **Log in** at `/login` with either your username or your email.
- **Forgot password?** Use the link on the login page and enter your email. The app sends a reset link that is valid for 30 minutes and stops working once it has been used.
- To stop just anyone from creating an officer account, set `REGISTRATION_CODE`. People then need that code to sign up.

**Email delivery.** Reset emails are sent through SMTP when `SMTP_HOST` is set (see the table below). When it is not set, which is the normal case on a laptop, the app **prints the reset link in the terminal** where it is running, so you can copy it into your browser. Nothing is emailed in that mode.

## Configuration
Set these environment variables before starting the app:

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY` | signs login sessions and reset links | an insecure development key |
| `REGISTRATION_CODE` | code required to create an officer account | empty (anyone can sign up) |
| `SMTP_HOST`, `SMTP_PORT` | mail server for reset emails | not set (links are printed), `587` |
| `SMTP_USER`, `SMTP_PASS` | mail server login | empty |
| `MAIL_FROM` | sender address on reset emails | `SMTP_USER` |
| `DATABASE_URL` | database location | `sqlite:///violations.db` |
| `BASE_URL` | address encoded in QR codes (e.g. `http://192.168.1.20:5000`) | the address the page was opened with |
| `HOST`, `PORT` | where the server listens | `0.0.0.0`, `5000` |
| `FLASK_DEBUG` | set to `1` to enable the debugger (development only) | off |

Windows PowerShell:
```powershell
$env:SECRET_KEY = "a-long-random-string"
$env:REGISTRATION_CODE = "choose-a-code-to-share-with-officers"
python app.py
```
Mac/Linux: `SECRET_KEY=... REGISTRATION_CODE=... python app.py`

## Scanning the QR code with a phone
The QR code contains a link back to this app, so a phone can only open it if it can reach your computer:
1. Connect the phone and the computer to the **same Wi-Fi**.
2. On the computer, open the app using its network address, for example `http://192.168.1.20:5000`, not `localhost`. (Find the address with `ipconfig` on Windows or `ifconfig` on Mac/Linux.) Or set `BASE_URL` to that address.
3. Allow Python through the firewall if Windows asks.

## Running the tests
```bash
pip install pytest
pytest -q
```
The tests use an in-memory database and cover sign-up, login, the full forgot-password flow (including expired and reused links), CSRF protection, input validation, search, marking as paid, the challan and status pages, and QR code generation.

## Project structure
```
app.py              the whole app: models, routes and HTML templates
tests/test_app.py   automated tests
requirements.txt
instance/           the SQLite database (created at runtime, not in git)
```

## Limitations
- This is a learning project, not a system for real enforcement.
- All officer accounts have the same permissions, and there is no audit trail of who added or changed a record.
- There is no limit on failed login attempts, so use a strong password and keep the app on a private network.
- Without `REGISTRATION_CODE`, anyone who can reach the app can create an officer account and issue fines.
- The history and status pages are public, so anyone who can reach the app can see vehicle numbers and fines. Keep it on a private network, or add a login to those pages first.
- Challan IDs are sequential, so status pages can be guessed.
- The server uses plain HTTP; put it behind HTTPS for any real use.
- Bootstrap loads from a CDN, so styling needs an internet connection.
- The development server is not meant for production.

## License
MIT
