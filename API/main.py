import os
import json
import logging
import secrets
from datetime import datetime, timedelta
import sqlite3
import shutil

from fastapi import FastAPI, HTTPException, Request
from typing import Optional
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from passlib.hash import bcrypt
from dotenv import load_dotenv, find_dotenv

# ---------- logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from a .env file in this dir or any parent
try:
    dotenv_path = find_dotenv(usecwd=True)
    if dotenv_path:
        load_dotenv(dotenv_path)
        logger.info(f"Loaded environment from {dotenv_path}")
    else:
        logger.info("No .env file found")
except Exception as e:
    logger.warning(f"dotenv load skipped: {e}")

# ---------- FastAPI + CORS ----------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

"""
SQLite storage for user accounts
Table: users
  - id INTEGER PRIMARY KEY AUTOINCREMENT
  - full_name TEXT NOT NULL
  - email TEXT NOT NULL UNIQUE
  - password_hash TEXT NOT NULL
  - created_at TEXT NOT NULL (ISO timestamp UTC)
  - status TEXT NOT NULL ('pending' | 'active')
  - otp_code TEXT NULL
  - otp_expiry TEXT NULL (ISO timestamp UTC)
"""

DATA_ROOT = os.environ.get("BODYCHECK_DATA_ROOT") or os.path.dirname(__file__)

# Ensure separate folders for users and logins
USERS_DB_PATH = os.environ.get("USERS_DB_PATH") or os.path.join(DATA_ROOT, "users", "UserData.db")
LOGINS_DB_PATH = os.environ.get("LOGINS_DB_PATH") or os.path.join(DATA_ROOT, "logins", "logins.db")

os.makedirs(os.path.dirname(USERS_DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(LOGINS_DB_PATH), exist_ok=True)

# Migrate legacy DBs in API root if present and targets don't exist
try:
    legacy_users = os.path.join(os.path.dirname(__file__), "UserData.db")
    if not os.path.exists(USERS_DB_PATH) and os.path.exists(legacy_users):
        shutil.copy2(legacy_users, USERS_DB_PATH)
        logger.info(f"Migrated legacy users DB from {legacy_users} -> {USERS_DB_PATH}")
except Exception as e:
    logger.warning(f"Users DB migration skipped: {e}")

try:
    legacy_logins_candidates = [
        os.path.join(os.path.dirname(__file__), "logins.ds"),
        os.path.join(os.path.dirname(__file__), "logins.db"),
    ]
    legacy_logins = next((p for p in legacy_logins_candidates if os.path.exists(p)), None)
    if not os.path.exists(LOGINS_DB_PATH) and legacy_logins:
        shutil.copy2(legacy_logins, LOGINS_DB_PATH)
        logger.info(f"Migrated legacy login events DB from {legacy_logins} -> {LOGINS_DB_PATH}")
except Exception as e:
    logger.warning(f"Login events DB migration skipped: {e}")

users_conn = sqlite3.connect(USERS_DB_PATH, check_same_thread=False)
users_conn.row_factory = sqlite3.Row

events_conn = sqlite3.connect(LOGINS_DB_PATH, check_same_thread=False)
events_conn.row_factory = sqlite3.Row

def init_users_db():
    try:
        with users_conn:
            users_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    otp_code TEXT,
                    otp_expiry TEXT
                )
                """
            )
        logger.info(f"Users SQLite initialized at {USERS_DB_PATH}")
    except Exception as e:
        logger.error(f"Failed to initialize users SQLite DB: {e}")

def init_logins_db():
    try:
        with events_conn:
            events_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS login_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    user_email TEXT NOT NULL,
                    login_at TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                )
                """
            )
        logger.info(f"Login events SQLite initialized at {LOGINS_DB_PATH}")
    except Exception as e:
        logger.error(f"Failed to initialize login events SQLite DB: {e}")

def init_contact_forms_db():
    try:
        with users_conn:
            users_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS contact_forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT,
                    email TEXT NOT NULL,
                    role TEXT,
                    organization TEXT,
                    subject TEXT,
                    message TEXT,
                    created_at TEXT NOT NULL,
                    ip_address TEXT
                )
                """
            )
        logger.info("Contact forms SQLite table initialized")
    except Exception as e:
        logger.error(f"Failed to initialize contact forms SQLite table: {e}")

def get_user_by_email(email: str):
    cur = users_conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    return dict(row) if row else None

def create_user_pending(full_name: str, email: str, password_hash: str, otp_code: str, otp_expiry: str):
    created_at = datetime.utcnow().isoformat()
    with users_conn:
        users_conn.execute(
            """
            INSERT INTO users (full_name, email, password_hash, created_at, status, otp_code, otp_expiry)
            VALUES (?, ?, ?, ?, 'pending', ?, ?)
            """,
            (full_name, email, password_hash, created_at, otp_code, otp_expiry),
        )

def set_user_status(email: str, status: str):
    with users_conn:
        users_conn.execute("UPDATE users SET status = ? WHERE email = ?", (status, email))

def set_user_otp(email: str, otp_code: str, otp_expiry: str):
    with users_conn:
        users_conn.execute("UPDATE users SET otp_code = ?, otp_expiry = ? WHERE email = ?", (otp_code, otp_expiry, email))

def clear_user_otp(email: str):
    with users_conn:
        users_conn.execute("UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE email = ?", (email,))

def update_user_password(email: str, new_password_hash: str):
    with users_conn:
        users_conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (new_password_hash, email))

# ---------- Login event logging ----------
def log_login_event(user_id: Optional[int], user_email: str, success: bool, ip_address: Optional[str], user_agent: Optional[str]):
    with events_conn:
        events_conn.execute(
            """
            INSERT INTO login_events (user_id, user_email, login_at, success, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                user_email,
                datetime.utcnow().isoformat(),
                1 if success else 0,
                ip_address,
                user_agent,
            ),
        )

# Initialize databases on startup
init_users_db()
init_logins_db()
init_contact_forms_db()

# ---------- Email (SendGrid) utility ----------
try:
    from config import SENDGRID_API_KEY, SENDGRID_FROM_EMAIL, OTP_TTL_MINUTES
except ImportError:
    # Fallback to environment variables if config.py doesn't exist
    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
    SENDGRID_FROM_EMAIL = os.environ.get("SENDGRID_FROM_EMAIL")
    OTP_TTL_MINUTES = int(os.environ.get("OTP_TTL_MINUTES", 15))

def send_otp_email(recipient_email: str, otp_code: str, purpose: str = "verification"):
    if not SENDGRID_API_KEY or not SENDGRID_FROM_EMAIL:
        logger.warning("SendGrid credentials not set; skipping sending email (development mode)")
        return False, "SendGrid not configured"
    try:
        # Import sendgrid here to avoid dependency issues if not installed
        import sendgrid
        from sendgrid.helpers.mail import Mail, Email, To, Content

        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)

        if purpose == "signup":
            subject = "Verify Your BodyCheck Account"
            content_text = f"""Hello,
        
        Welcome to BodyCheck! 🎉
        
        To complete your registration, please verify your account using the code below:
        
        🔑 Verification Code: {otp_code}
        
        ⚠️ Note: This code will expire in {OTP_TTL_MINUTES} minutes.
        
        If you did not sign up for BodyCheck, you can safely ignore this email.
        
        Best regards,  
        The BodyCheck Team
        """
        else:
            subject = "Reset Your BodyCheck Password"
            content_text = f"""Hello,
        
        We received a request to reset your BodyCheck password.  
        Use the code below to proceed:
        
        🔑 OTP Code: {otp_code}
        
        ⚠️ Note: This code will expire in {OTP_TTL_MINUTES} minutes.
        
        If you did not request a password reset, please ignore this email.
        
        Best regards,  
        BodyCheck Team"""

        from_email = Email(SENDGRID_FROM_EMAIL)
        to_email = To(recipient_email)
        content = Content("text/plain", content_text)
        mail = Mail(from_email, to_email, subject, content)

        response = sg.send(mail)

        if response.status_code in [200, 201, 202]:
            logger.info(f"Sent {purpose} OTP email to {recipient_email}")
            return True, None
        else:
            logger.error(f"SendGrid API error: {response.status_code} - {response.body}")
            return False, f"SendGrid API error: {response.status_code}"
    except ImportError:
        logger.error("SendGrid library not installed. Please install with: pip install sendgrid")
        return False, "SendGrid library not installed"
    except Exception as e:
        logger.error(f"Failed to send email via SendGrid: {e}")
        return False, str(e)
def send_admin_notification_email(subject: str, content_text: str):
    """
    Send an email notification to admin(s) when a new user signs up or a contact form is submitted.
    For testing, always send to diptisharma@enestit.com.
    """
    if not SENDGRID_API_KEY:
        logger.warning("SendGrid credentials not set; skipping admin notification email (development mode)")
        return False, "SendGrid not configured"
    if not SENDGRID_FROM_EMAIL:
        logger.warning("SENDGRID_FROM_EMAIL not set; using default sender")
    try:
        import sendgrid
        from sendgrid.helpers.mail import Mail, Email, To, Content

        admin_email = "jack.smith@bodycheck.ai"  # Replace with your admin email
        from_email = Email(SENDGRID_FROM_EMAIL or admin_email)
        to_email = To(admin_email)
        content = Content("text/plain", content_text)
        mail = Mail(from_email, to_email, subject, content)
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        response = sg.send(mail)
        if response.status_code not in [200, 201, 202]:
            logger.error(f"SendGrid admin notification error: {response.status_code} - {response.body}")
            return False, f"SendGrid API error: {response.status_code}"
        logger.info(f"Sent admin notification email to {admin_email}")
        return True, None
    except ImportError:
        logger.error("SendGrid library not installed. Please install with: pip install sendgrid")
        return False, "SendGrid library not installed"
    except Exception as e:
        logger.error(f"Failed to send admin notification email: {e}")
        return False, str(e)

# ---------- Pydantic models ----------
class SignupData(BaseModel):
    full_name: str
    email: str
    password: str

class SignupVerifyData(BaseModel):
    email: str
    otp: str

class LoginData(BaseModel):
    email: str
    password: str

class ForgotRequest(BaseModel):
    email: str

class ResetRequest(BaseModel):
    email: str
    otp: str
    new_password: str

class ContactFormData(BaseModel):
    name: Optional[str] = None
    email: str
    role: Optional[str] = None
    organization: Optional[str] = None
    message: str
    subject: Optional[str] = None

# ---------- Admin utilities and endpoints ----------
def _get_admin_emails():
    raw = os.environ.get("ADMIN_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}

def _require_admin_from_headers(request: Request):
    admin_email = request.headers.get("X-Admin-Email")
    admin_password = request.headers.get("X-Admin-Password")
    # hardcoded admin for testing
    if admin_email == "vishnu@example.com" and admin_password == "123":
        return {"email": admin_email, "status": "active"}
    if not admin_email or not admin_password:
        raise HTTPException(status_code=401, detail="Missing admin credentials")
    admin_email_lc = admin_email.strip().lower()
    allowed = _get_admin_emails()
    if allowed and admin_email_lc not in allowed:
        raise HTTPException(status_code=403, detail="Not an admin account")
    user = get_user_by_email(admin_email_lc)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    if user.get("status") != "active":
        raise HTTPException(status_code=403, detail="Admin account not active")
    stored_pw = user.get("password_hash") or ""
    if not bcrypt.verify(admin_password, stored_pw):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return user

def _list_users(limit: Optional[int] = None):
    query = "SELECT id, full_name, email, created_at, status FROM users ORDER BY datetime(created_at) DESC"
    if limit is not None:
        cur = users_conn.execute(query + " LIMIT ?", (int(limit),))
    else:
        cur = users_conn.execute(query)
    return [dict(r) for r in cur.fetchall()]

def _list_login_events(limit: Optional[int] = None):
    query = (
        "SELECT id, user_id, user_email, login_at, success, ip_address, user_agent "
        "FROM login_events ORDER BY datetime(login_at) DESC"
    )
    if limit is not None:
        cur = events_conn.execute(query + " LIMIT ?", (int(limit),))
    else:
        cur = events_conn.execute(query)
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        r["success"] = bool(r.get("success"))
    return rows

def _list_contact_forms(limit: Optional[int] = None):
    query = (
        "SELECT id, full_name, email, role, organization, subject, message, created_at, ip_address "
        "FROM contact_forms ORDER BY datetime(created_at) DESC"
    )
    if limit is not None:
        cur = users_conn.execute(query + " LIMIT ?", (int(limit),))
    else:
        cur = users_conn.execute(query)
    return [dict(r) for r in cur.fetchall()]

@app.get("/admin/data")
async def admin_all_data(request: Request, users_limit: Optional[int] = None, events_limit: Optional[int] = None):
    _require_admin_from_headers(request)
    users = _list_users(users_limit)
    events = _list_login_events(events_limit)
    totals = _list_users()
    total_events = _list_login_events()
    stats = {
        "total_users": len(totals),
        "total_events": len(total_events),
        "active_users": sum(1 for u in totals if u.get("status") == "active"),
        "pending_users": sum(1 for u in totals if u.get("status") == "pending"),
    }
    return {"users": users, "login_events": events, "stats": stats}

@app.get("/admin/contact_forms")
async def admin_contact_forms(request: Request, limit: Optional[int] = None):
    _require_admin_from_headers(request)
    rows = _list_contact_forms(limit)
    return {"contact_forms": rows}

# ---------- Signup with OTP verification ----------
@app.post("/signup")
async def signup(data: SignupData):
    try:
        existing = get_user_by_email(data.email)
        # if existing:
        #     raise HTTPException(status_code=400, detail="Email already registered")

        # generate 6-digit OTP
        otp_code = f"{secrets.randbelow(10**6):06d}"
        expiry = (datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()

        # store signup data temporarily with OTP
        password_hash = bcrypt.hash(data.password)
        try:
            create_user_pending(data.full_name, data.email, password_hash, otp_code, expiry)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Email already registered")
        logger.info(f"Signup initiated for: {data.email}")

        # send OTP email
        sent, err = send_otp_email(data.email, otp_code, "signup")
        if not sent:
            logger.error(f"Failed to send signup OTP email: {err}")

        return {"message": "Signup initiated. Please check your email for OTP verification."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save data: {e}")

@app.post("/signup-verify")
async def signup_verify(data: SignupVerifyData):
    try:
        user = get_user_by_email(data.email)
        if not user:
            raise HTTPException(status_code=404, detail="Signup request not found")
        status = user.get("status", "")
        if status != "pending":
            raise HTTPException(status_code=400, detail="Invalid signup status")

        otp_stored = user.get("otp_code", "")
        otp_expiry = user.get("otp_expiry", "")


        if not otp_stored:
            raise HTTPException(status_code=400, detail="No OTP found for this signup")

        # check expiry
        try:
            # Handle different datetime formats
            if otp_expiry:
                try:
                    expiry_dt = datetime.fromisoformat(otp_expiry)
                except ValueError:
                    try:
                        # Try parsing as regular datetime string
                        expiry_dt = datetime.strptime(otp_expiry, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        # Try parsing without microseconds
                        expiry_dt = datetime.strptime(otp_expiry.split('.')[0], "%Y-%m-%dT%H:%M:%S")
            else:
                raise HTTPException(status_code=400, detail="OTP expired")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid OTP expiry format")

        if datetime.utcnow() > expiry_dt:
            raise HTTPException(status_code=400, detail="OTP expired")

        # verify OTP
        if str(otp_stored).strip() != str(data.otp).strip():
            raise HTTPException(status_code=401, detail="Invalid OTP")

        # activate account
        set_user_status(data.email, "active")
        clear_user_otp(data.email)

        # send admin notification now that user is active
        admin_subject = "[BodyCheck] New User Signup Notification"
        
        admin_content = (
            "Hello Admin,\n\n"
            "A new user has successfully signed up on BodyCheck.\n\n"
            f"📧 Email Address : {data.email}\n"
            f"👤 Full Name     : {user.get('full_name', 'N/A')}\n"
            f"🕒 Signup Time   : {datetime.utcnow().isoformat()} UTC\n\n"
            "You may review this account in the admin dashboard.\n\n"
            "— BodyCheck System Notification"
        )
        
        send_admin_notification_email(admin_subject, admin_content)

        logger.info(f"Signup verified successfully for: {data.email}")
        return {"message": "Signup verified successfully! You can now login."}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup verify error: {e}")
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")

# ---------- Login (updated to check for active status) ----------
@app.post("/login")
async def login(data: LoginData, request: Request):
    logger.info(f"Login attempt for: {data.email}")
    try:
        user = get_user_by_email(data.email)
        if not user:
            logger.warning(f"User not found: {data.email}")
            # record failed attempt
            ip = request.client.host if request and request.client else None
            ua = request.headers.get("user-agent") if request else None
            log_login_event(None, data.email, False, ip, ua)
            raise HTTPException(status_code=404, detail="User not found")
        
        status = user.get("status", "")
        
        # check if account is active
        if status == "pending":
            ip = request.client.host if request and request.client else None
            ua = request.headers.get("user-agent") if request else None
            log_login_event(user.get("id"), data.email, False, ip, ua)
            raise HTTPException(status_code=401, detail="Account not verified. Please check your email for OTP.")
        
        stored_pw = user.get("password_hash") or ""
        ip = request.client.host if request and request.client else None
        ua = request.headers.get("user-agent") if request else None
        if bcrypt.verify(data.password, stored_pw):
            logger.info(f"Login success for {data.email}")
            log_login_event(user.get("id"), data.email, True, ip, ua)
            return {"message": "Login successful", "full_name": user.get("full_name")}
        else:
            logger.warning(f"Invalid password for {data.email}")
            log_login_event(user.get("id"), data.email, False, ip, ua)
            raise HTTPException(status_code=401, detail="Invalid password")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {e}")

# ---------- Forgot password (send OTP) ----------

@app.post("/forgot-password")
async def forgot_password(req: ForgotRequest):
    try:
        user = get_user_by_email(req.email)
        if not user:
            logger.warning(f"Forgot password requested for unknown email: {req.email}")
            # for security, don't reveal whether email exists; still return success
            return {"message": "If that email exists, an OTP has been sent"}
        # generate 6-digit OTP
        otp_code = f"{secrets.randbelow(10**6):06d}"
        expiry = (datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()
        # update user with OTP
        set_user_otp(req.email, otp_code, expiry)
        # send email (best-effort)
        sent, err = send_otp_email(req.email, otp_code)
        if not sent:
            logger.error(f"Failed to send OTP email: {err}")
            # still return generic message
            return {"message": "If that email exists, an OTP has been stored (email failed)"}
        return {"message": "If that email exists, an OTP has been sent"}
    except Exception as e:
        logger.error(f"forgot-password error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process request: {e}")

# ---------- Reset password using OTP ----------
@app.post("/reset-password")
async def reset_password(req: ResetRequest):
    try:
        user = get_user_by_email(req.email)
        if not user:
            logger.warning(f"Reset attempt for unknown email: {req.email}")
            raise HTTPException(status_code=404, detail="User not found")
        otp_stored = user.get("otp_code", "")
        otp_expiry = user.get("otp_expiry", "")
        if not otp_stored:
            raise HTTPException(status_code=400, detail="No OTP requested for this account")
        # compare expiry
        try:
            # Handle different datetime formats
            if otp_expiry:
                try:
                    expiry_dt = datetime.fromisoformat(otp_expiry)
                except ValueError:
                    try:
                        # Try parsing as regular datetime string
                        expiry_dt = datetime.strptime(otp_expiry, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        # Try parsing without microseconds
                        expiry_dt = datetime.strptime(otp_expiry.split('.')[0], "%Y-%m-%dT%H:%M:%S")
            else:
                raise HTTPException(status_code=400, detail="OTP expired")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid OTP expiry format on server")
        if datetime.utcnow() > expiry_dt:
            raise HTTPException(status_code=400, detail="OTP expired")
        if str(otp_stored) != str(req.otp):
            raise HTTPException(status_code=401, detail="Invalid OTP")
        # all good -> update password (hash)
        new_hash = bcrypt.hash(req.new_password)
        update_user_password(req.email, new_hash)
        # clear OTP fields
        clear_user_otp(req.email)
        logger.info(f"Password reset successful for: {req.email}")
        return {"message": "Password reset successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"reset-password error: {e}")
        raise HTTPException(status_code=500, detail=f"Reset failed: {e}")

# ---------- Contact form ----------
@app.post("/contact")
async def contact_submit(data: ContactFormData, request: Request):
    try:
        created_at = datetime.utcnow().isoformat()
        ip = request.client.host if request and request.client else None
        with users_conn:
            users_conn.execute(
                """
                INSERT INTO contact_forms (full_name, email, role, organization, subject, message, created_at, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data.name or None,
                    data.email,
                    data.role or None,
                    data.organization or None,
                    data.subject or None,
                    data.message,
                    created_at,
                    ip,
                ),
            )
        logger.info(f"Contact form submitted by {data.email}")

        # send admin notification
        admin_subject = "[BodyCheck] New Contact Form Submission"
        
        admin_content = (
            "Hello Admin,\n\n"
            "A new contact form has been submitted on BodyCheck.\n\n"
            f"👤 Name         : {data.name or 'N/A'}\n"
            f"📧 Email        : {data.email}\n"
            f"🏷️ Role         : {data.role or 'N/A'}\n"
            f"🏢 Organization : {data.organization or 'N/A'}\n"
            f"💬 Message      : {data.message}\n"
            f"🕒 Submitted At : {created_at}\n\n"
            "Please review and follow up accordingly.\n\n"
            "— BodyCheck System Notification"
        )
        send_admin_notification_email(admin_subject, admin_content)

        return {"message": "Thanks for reaching out. Our team will contact you soon."}
    except Exception as e:
        logger.error(f"contact submit error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit contact form: {e}")

# ---------- Health check ----------
@app.get("/health")
async def health_check():
    try:
        # Simple DB queries to confirm connectivity
        users_count = users_conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        events_count = events_conn.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]
        return {
            "status": "healthy",
            "users_db_path": USERS_DB_PATH,
            "logins_db_path": LOGINS_DB_PATH,
            "user_count": users_count,
            "login_events_count": events_count,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


