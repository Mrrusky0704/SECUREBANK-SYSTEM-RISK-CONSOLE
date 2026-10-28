from __future__ import annotations
import os, sqlite3, time, secrets, hashlib, hmac
from pathlib import Path
from decimal import Decimal, InvalidOperation
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort

# Configurable speed-profiling threshold
MIN_HUMAN_INTERACTION_SECONDS = 5.0
DATABASE_PATH = Path(__file__).with_name("bank.db")
SECRET_KEY = os.environ.get("BANK_APP_SECRET", "dev-only-change-this-secret-key")
ADMIN_USERNAME = os.environ.get("BANK_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("BANK_ADMIN_PASSWORD", "ChangeMe123!")

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None: conn.close()

def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)

def password_matches(password, salt, digest):
    return hmac.compare_digest(password_hash(password, salt)[1], digest)

def init_db():
    with app.app_context():
        conn = db()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE, salt BLOB NOT NULL,
          password_hash BLOB NOT NULL, role TEXT NOT NULL DEFAULT 'customer'
          CHECK(role IN ('customer','admin')), is_frozen INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS accounts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
          account_number TEXT NOT NULL UNIQUE, balance_paise INTEGER NOT NULL DEFAULT 0 CHECK(balance_paise>=0),
          created_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS transactions (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
          account_id INTEGER NOT NULL REFERENCES accounts(id), recipient_account TEXT NOT NULL,
          amount_paise INTEGER NOT NULL CHECK(amount_paise>0),
          status TEXT NOT NULL CHECK(status IN ('Completed','Pending Admin Audit','Rejected')),
          risk_score INTEGER NOT NULL DEFAULT 0, interaction_duration REAL,
          created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_by INTEGER REFERENCES users(id),
          reviewed_at TEXT, review_note TEXT);
        CREATE TABLE IF NOT EXISTS anomalies (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id),
          transaction_id INTEGER REFERENCES transactions(id), anomaly_type TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'High', details TEXT NOT NULL, interaction_duration REAL,
          created_at TEXT NOT NULL DEFAULT (datetime('now')), resolved INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_tx_created ON transactions(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_anomaly_created ON anomalies(created_at DESC);
        """)
        if not conn.execute("SELECT id FROM users WHERE username=?", (ADMIN_USERNAME,)).fetchone():
            salt, digest = password_hash(ADMIN_PASSWORD)
            conn.execute("INSERT INTO users(full_name,username,salt,password_hash,role) VALUES(?,?,?,?,?)",
                         ("System Administrator", ADMIN_USERNAME, salt, digest, "admin"))
        conn.commit()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"): return redirect(url_for("login"))
        user = db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or user["is_frozen"]:
            session.clear(); flash("This account is unavailable. Contact an administrator.", "error")
            return redirect(url_for("login"))
        g.current_user = user
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if g.current_user["role"] != "admin": abort(403)
        return fn(*args, **kwargs)
    return wrapped

def money_to_paise(raw):
    try: amount = Decimal(raw.strip())
    except (InvalidOperation, AttributeError) as exc: raise ValueError("Enter a valid amount.") from exc
    if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
        raise ValueError("Amount must be positive and have at most two decimal places.")
    return int(amount * 100)

def rupees(paise): return f"₹{int(paise)//100:,}.{int(paise)%100:02d}"
@app.template_filter("money")
def money_filter(paise): return rupees(paise)

def record_anomaly(user_id, tx_id, kind, details, duration):
    db().execute("""INSERT INTO anomalies(user_id,transaction_id,anomaly_type,severity,details,
                    interaction_duration) VALUES(?,?,?,'High',?,?)""",
                 (user_id, tx_id, kind, details, duration))

def handle_high_risk_submission(duration, reason, received_ms):
    uid = session["user_id"]
    recipient = request.form.get("recipient_account", "").strip() or "(not supplied)"
    try: amount = money_to_paise(request.form.get("amount", ""))
    except ValueError:
        amount = 1
        recipient = "(invalid request)"
    account = db().execute("SELECT * FROM accounts WHERE user_id=?", (uid,)).fetchone()
    db().execute("""INSERT INTO transactions(user_id,account_id,recipient_account,amount_paise,
                 status,risk_score,interaction_duration) VALUES(?,?,?,?,'Pending Admin Audit',100,?)""",
                 (uid, account["id"], recipient, amount, duration))
    tx_id = db().execute("SELECT last_insert_rowid()").fetchone()[0]
    record_anomaly(uid, tx_id, "High-Risk Bot Interception",
                   f"{reason} Backend receipt epoch-ms={received_ms}; duration={duration:.3f}s. "
                   "Transaction was not executed.", duration)
    db().commit()
    return render_template("security.html", duration=f"{duration:.3f}",
                           threshold=MIN_HUMAN_INTERACTION_SECONDS, tx_id=tx_id), 202

def speed_profile_required(fn):
    """One-use form timestamp + backend receipt timestamp. Fast requests go to audit, never execute."""
    @wraps(fn)
    def wrapped(*args, **kwargs):
        submission_time = time.time_ns() // 1_000_000  # exact millisecond resolution
        session_start_time = session.pop("transaction_form_started_ms", None)
        if session_start_time is None:
            duration, reason = 0.0, "Missing or expired transaction-form session marker."
        else:
            duration = max(0.0, (submission_time - int(session_start_time)) / 1000.0)
            reason = "Submission arrived below the minimum interaction threshold."
        if duration < MIN_HUMAN_INTERACTION_SECONDS:
            return handle_high_risk_submission(duration, reason, submission_time)
        request.environ["bank_interaction_duration"] = duration
        return fn(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("admin_dashboard" if session.get("role") == "admin" else "dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name=request.form.get("full_name","").strip(); username=request.form.get("username","").strip()
        password=request.form.get("password","")
        if len(name)<2 or len(username)<3 or any(c.isspace() for c in username):
            flash("Name must be 2+ characters; username must be 3+ characters without spaces.","error")
        elif len(password)<8: flash("Password must contain at least 8 characters.","error")
        else:
            salt,digest=password_hash(password)
            try:
                cur=db().execute("INSERT INTO users(full_name,username,salt,password_hash) VALUES(?,?,?,?)",
                                 (name,username,salt,digest))
                uid=cur.lastrowid
                while True:
                    number="10"+"".join(secrets.choice("0123456789") for _ in range(10))
                    if not db().execute("SELECT 1 FROM accounts WHERE account_number=?",(number,)).fetchone(): break
                db().execute("INSERT INTO accounts(user_id,account_number) VALUES(?,?)",(uid,number)); db().commit()
                flash(f"Account created. Account number: {number}. Please log in.","success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                db().rollback(); flash("That username is already taken.","error")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username=request.form.get("username","").strip(); password=request.form.get("password","")
        user=db().execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if user and not user["is_frozen"] and password_matches(password,user["salt"],user["password_hash"]):
            session.clear(); session.update(user_id=user["id"],role=user["role"],username=user["username"])
            return redirect(url_for("admin_dashboard" if user["role"]=="admin" else "dashboard"))
        flash("Invalid credentials or account unavailable.","error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); flash("You have logged out.","success"); return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    account=db().execute("SELECT * FROM accounts WHERE user_id=?",(g.current_user["id"],)).fetchone()
    tx=db().execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 25",(g.current_user["id"],)).fetchall()
    return render_template("dashboard.html", user=g.current_user, account=account, transactions=tx)

@app.route("/transaction/new")
@login_required
def transaction_form():
    session["transaction_form_started_ms"] = time.time_ns() // 1_000_000
    return render_template("transaction.html", threshold=MIN_HUMAN_INTERACTION_SECONDS)

@app.post("/transaction/submit")
@login_required
@speed_profile_required
def execute_transaction():
    recipient_no=request.form.get("recipient_account","").strip()
    try: amount=money_to_paise(request.form.get("amount",""))
    except ValueError as exc: flash(str(exc),"error"); return redirect(url_for("transaction_form"))
    conn=db(); conn.execute("BEGIN IMMEDIATE")
    sender=conn.execute("SELECT * FROM accounts WHERE user_id=?",(g.current_user["id"],)).fetchone()
    recipient=conn.execute("SELECT * FROM accounts WHERE account_number=?",(recipient_no,)).fetchone()
    if not recipient:
        conn.rollback(); flash("Recipient account was not found.","error"); return redirect(url_for("transaction_form"))
    if recipient["id"]==sender["id"]:
        conn.rollback(); flash("You cannot transfer to your own account.","error"); return redirect(url_for("transaction_form"))
    if amount>sender["balance_paise"]:
        conn.rollback(); flash("Insufficient funds. This demo has no cash-deposit UI.","error"); return redirect(url_for("transaction_form"))
    conn.execute("UPDATE accounts SET balance_paise=balance_paise-? WHERE id=?",(amount,sender["id"]))
    conn.execute("UPDATE accounts SET balance_paise=balance_paise+? WHERE id=?",(amount,recipient["id"]))
    conn.execute("""INSERT INTO transactions(user_id,account_id,recipient_account,amount_paise,status,
                 risk_score,interaction_duration) VALUES(?,?,?,?,'Completed',0,?)""",
                 (g.current_user["id"],sender["id"],recipient_no,amount,request.environ["bank_interaction_duration"]))
    conn.commit(); flash(f"Transfer completed: {rupees(amount)} sent to {recipient_no}.","success")
    return redirect(url_for("dashboard"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn=db()
    stats={
      "users":conn.execute("SELECT COUNT(*) FROM users WHERE role='customer'").fetchone()[0],
      "frozen":conn.execute("SELECT COUNT(*) FROM users WHERE role='customer' AND is_frozen=1").fetchone()[0],
      "transactions":conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0],
      "pending":conn.execute("SELECT COUNT(*) FROM transactions WHERE status='Pending Admin Audit'").fetchone()[0],
      "open_anomalies":conn.execute("SELECT COUNT(*) FROM anomalies WHERE resolved=0").fetchone()[0],
      "completed":conn.execute("SELECT COUNT(*) FROM transactions WHERE status='Completed'").fetchone()[0],
      "rejected":conn.execute("SELECT COUNT(*) FROM transactions WHERE status='Rejected'").fetchone()[0]}
    anomalies=conn.execute("""SELECT a.*,u.username FROM anomalies a LEFT JOIN users u ON u.id=a.user_id
                              ORDER BY a.id DESC LIMIT 10""").fetchall()
    tx=conn.execute("""SELECT t.*,u.username FROM transactions t JOIN users u ON u.id=t.user_id
                       ORDER BY t.id DESC LIMIT 10""").fetchall()
    chart=conn.execute("""SELECT CASE WHEN status='Pending Admin Audit' THEN 'Pending Audit'
                         WHEN status='Rejected' THEN 'Rejected' ELSE 'Completed' END AS label,COUNT(*) AS n
                         FROM transactions GROUP BY label""").fetchall()
    return render_template("admin.html",stats=stats,anomalies=anomalies,transactions=tx,chart=chart)

@app.route("/admin/users")
@admin_required
def admin_users():
    users=db().execute("""SELECT u.id,u.full_name,u.username,u.role,u.is_frozen,u.created_at,
                          a.account_number,a.balance_paise FROM users u LEFT JOIN accounts a ON a.user_id=u.id
                          ORDER BY u.id DESC""").fetchall()
    return render_template("users.html",users=users)

@app.post("/admin/users/<int:user_id>/freeze")
@admin_required
def toggle_freeze(user_id):
    if user_id==g.current_user["id"]:
        flash("You cannot freeze your own admin account.","error"); return redirect(url_for("admin_users"))
    user=db().execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not user or user["role"]=="admin": abort(404)
    frozen=0 if user["is_frozen"] else 1
    db().execute("UPDATE users SET is_frozen=? WHERE id=?",(frozen,user_id)); db().commit()
    flash(f"User {user['username']} {'unfrozen' if not frozen else 'frozen'}.","success")
    return redirect(url_for("admin_users"))

@app.post("/admin/users/<int:user_id>/credit")
@admin_required
def credit_test_funds(user_id):
    # Demo-only funding helper; in real banking this must be an audited deposit workflow.
    raw_amount = request.form.get("amount", "")
    try:
        amount = money_to_paise(raw_amount)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin_users"))
    account = db().execute("SELECT * FROM accounts WHERE user_id=?", (user_id,)).fetchone()
    user = db().execute("SELECT * FROM users WHERE id=? AND role='customer'", (user_id,)).fetchone()
    if not user or not account:
        abort(404)
    new_balance = account["balance_paise"] + amount
    db().execute("UPDATE accounts SET balance_paise=? WHERE id=?", (new_balance, account["id"]))
    # Represent demo funding in the transaction log; the transaction type is described in the note.
    db().execute("""INSERT INTO transactions(user_id,account_id,recipient_account,amount_paise,status,
                 risk_score,interaction_duration,reviewed_by,reviewed_at,review_note)
                 VALUES(?,?,? ,?,'Completed',0,NULL,?,datetime('now'),'Admin demo funding')""",
                 (user_id, account["id"], "ADMIN DEMO CREDIT", amount, g.current_user["id"]))
    db().commit()
    flash(f"Added {rupees(amount)} in demo funds to {user['username']}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/transactions")
@admin_required
def admin_transactions():
    tx=db().execute("""SELECT t.*,u.username FROM transactions t JOIN users u ON u.id=t.user_id
                       ORDER BY t.id DESC LIMIT 300""").fetchall()
    return render_template("transactions.html",transactions=tx)

@app.post("/admin/transactions/<int:tx_id>/review")
@admin_required
def review_transaction(tx_id):
    action=request.form.get("action"); note=request.form.get("note","").strip()[:500]
    conn=db(); tx=conn.execute("SELECT * FROM transactions WHERE id=?",(tx_id,)).fetchone()
    if not tx or tx["status"]!="Pending Admin Audit":
        flash("Only pending audit transactions can be reviewed.","error"); return redirect(url_for("admin_transactions"))
    if action=="reject":
        conn.execute("""UPDATE transactions SET status='Rejected',reviewed_by=?,reviewed_at=datetime('now'),
                        review_note=? WHERE id=?""",(g.current_user["id"],note or "Rejected by admin",tx_id))
        conn.execute("UPDATE anomalies SET resolved=1 WHERE transaction_id=?",(tx_id,))
    elif action=="approve":
        conn.execute("BEGIN IMMEDIATE")
        sender=conn.execute("SELECT * FROM accounts WHERE id=?",(tx["account_id"],)).fetchone()
        recipient=conn.execute("SELECT * FROM accounts WHERE account_number=?",(tx["recipient_account"],)).fetchone()
        if not recipient or recipient["id"]==sender["id"] or sender["balance_paise"]<tx["amount_paise"]:
            conn.rollback(); flash("Cannot approve: invalid recipient or insufficient funds.","error")
            return redirect(url_for("admin_transactions"))
        conn.execute("UPDATE accounts SET balance_paise=balance_paise-? WHERE id=?",(tx["amount_paise"],sender["id"]))
        conn.execute("UPDATE accounts SET balance_paise=balance_paise+? WHERE id=?",(tx["amount_paise"],recipient["id"]))
        conn.execute("""UPDATE transactions SET status='Completed',reviewed_by=?,reviewed_at=datetime('now'),
                        review_note=? WHERE id=?""",(g.current_user["id"],note or "Approved after admin audit",tx_id))
        conn.execute("UPDATE anomalies SET resolved=1 WHERE transaction_id=?",(tx_id,))
    else:
        flash("Choose approve or reject.","error"); return redirect(url_for("admin_transactions"))
    conn.commit(); flash(f"Transaction #{tx_id} reviewed.","success")
    return redirect(url_for("admin_transactions"))

@app.route("/admin/anomalies")
@admin_required
def admin_anomalies():
    rows=db().execute("""SELECT a.*,u.username FROM anomalies a LEFT JOIN users u ON u.id=a.user_id
                         ORDER BY a.id DESC LIMIT 500""").fetchall()
    return render_template("anomalies.html",anomalies=rows)

@app.post("/admin/anomalies/<int:anomaly_id>/resolve")
@admin_required
def resolve_anomaly(anomaly_id):
    db().execute("UPDATE anomalies SET resolved=1 WHERE id=?",(anomaly_id,)); db().commit()
    flash("Anomaly marked resolved.","success"); return redirect(url_for("admin_anomalies"))

@app.errorhandler(403)
def forbidden(_): return render_template("error.html",code=403,message="Administrator access required."),403
@app.errorhandler(404)
def not_found(_): return render_template("error.html",code=404,message="Page not found."),404

if __name__=="__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG")=="1")
