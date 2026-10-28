# SecureBank — Python Bank Management + Speed/Interaction Risk Profiling

## Features
- Customer registration/login, generated account number, persistent SQLite accounts and transfer history.
- Salted PBKDF2-HMAC-SHA256 password hashes.
- Admin overview with KPIs and Chart.js transaction-status chart.
- Admin user management: freeze/unfreeze customers and add clearly labelled demo funds to test transfers.
- Transaction review: approve/reject transfers held for audit.
- Anomaly centre: High-Risk Bot Interception events, measured duration, severity and resolution.
- Speed profiling decorator around transaction submission.

## Speed profiling logic
`MIN_HUMAN_INTERACTION_SECONDS = 5.0` is at the top of `app.py`.
- `GET /transaction/new` records `session["transaction_form_started_ms"]`.
- The `@speed_profile_required` decorator captures `submission_time = time.time_ns() // 1_000_000` at backend receipt.
- It calculates `(submission_time - session_start_time) / 1000`.
- Under 5 seconds, the transfer is not executed. A `Pending Admin Audit` transaction and `High-Risk Bot Interception` anomaly are recorded, and a security verification/hold page is returned with HTTP 202.
- The session marker is one-use. An administrator can approve (with fresh balance/recipient validation) or reject the pending transaction.

## Run on Windows / VS Code
1. Extract the ZIP and open this folder in VS Code.
2. In Terminal run:
   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```
3. Set custom credentials before first run (recommended):
   ```powershell
   $env:BANK_ADMIN_USERNAME = "admin"
   $env:BANK_ADMIN_PASSWORD = "Use-A-Strong-Unique-Password"
   $env:BANK_APP_SECRET = "replace-with-a-long-random-secret"
   python app.py
   ```
4. Visit http://127.0.0.1:5000
5. Default local demo admin if no environment variables were set: `admin` / `ChangeMe123!`. The admin user is seeded only once; changing environment variables after database creation does not update that existing account.
6. Register two customer accounts to test transfers. Balances start at ₹0. In the admin Users page, use the clearly labelled **Add demo funds** form to fund test customer accounts and try transfers. This is a testing convenience, not a real deposit workflow.

## Structure
- `app.py`: routes, SQLite schema, authentication, transaction logic and profiling decorator
- `templates/`: customer pages and admin console
- `static/style.css`: responsive UI styling
- `requirements.txt`: Flask dependency

## Security caveat
Educational demonstration only, not production banking software. Interaction speed is a weak risk signal, not proof of automation. A bot can wait five seconds and a human may submit quickly. Production requires CSRF protection, server-side session storage, rate limiting, MFA/step-up checks, device and transaction risk signals, HTTPS, secure deployment, monitoring and security review. Set a strong secret, do not expose default credentials, and do not use real money or personal data. Chart.js and fonts load from CDNs.
