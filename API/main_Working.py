# Data Save to CSV

import os
import json
import logging
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

import gspread
from oauth2client.service_account import ServiceAccountCredentials
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from passlib.hash import bcrypt

# ---------- logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- FastAPI + CORS ----------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Google Sheets Auth ----------
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

# Prefer credentials from environment variables
# - GOOGLE_SERVICE_ACCOUNT_JSON: full JSON content
# - GOOGLE_APPLICATION_CREDENTIALS: path to JSON file
creds = None
client = None
try:
    service_account_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON")
    service_account_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")

    if service_account_json:
        creds_dict = json.loads(service_account_json)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
    elif service_account_path and os.path.exists(service_account_path):
        creds = ServiceAccountCredentials.from_json_keyfile_name(service_account_path, scope)
    elif os.path.exists("gen-lang-client-0972324769-f6bac2d207cd.json"):
        # Local dev fallback only; file should not be committed
        creds = ServiceAccountCredentials.from_json_keyfile_name(
            "gen-lang-client-0972324769-f6bac2d207cd.json", scope
        )

    if creds is not None:
        client = gspread.authorize(creds)
        logger.info("Google Sheets authentication successful")
    else:
        raise RuntimeError("No Google service account credentials provided")
except Exception as e:
    logger.error(f"Google Sheets authentication failed: {e}")
    client = None

# ---------- Open Sheet ----------
SHEET_ID = "1lMTiOU1Oa_7-41nTQOgBKWRTeUKHGyLAYBXb-c0rNyg"
sheet = None
headers = []
try:
    if client:
        sh = client.open_by_key(SHEET_ID)
        sheet = sh.get_worksheet(0)  # first worksheet
        headers = sheet.row_values(1)
        logger.info(f"Opened sheet; headers: {headers}")
    else:
        logger.error("Client is None; cannot open sheet")
except Exception as e:
    logger.error(f"Failed to open sheet: {e}")
    sheet = None
    headers = []

# ---------- Helper utilities for sheet operations ----------
def refresh_headers():
    global headers
    try:
        headers = sheet.row_values(1)
    except Exception as e:
        logger.error(f"Error refreshing headers: {e}")

def col_index(col_name: str):
    """
    Return 1-based column index for a header name. If column missing, return None.
    """
    try:
        refresh_headers()
        idx = headers.index(col_name) + 1
        return idx
    except ValueError:
        return None

def find_row_by_email(email: str):
    """
    Return row number (1-based) for the first occurrence of email in the Email column.
    If not found, returns None.
    """
    try:
        email_col = col_index("Email")
        if email_col is None:
            logger.error("Email column not found in sheet headers")
            return None
        cell = sheet.find(email, in_column=email_col)
        if cell:
            return cell.row
    except Exception:
        # sheet.find raises if not found -> handle silently
        return None
    return None

def get_row_record(row: int):
    """
    Return dict mapping header->value for the given 1-based row number.
    """
    row_values = sheet.row_values(row)
    # ensure list length equals headers length for mapping
    values = row_values + [""] * (len(headers) - len(row_values))
    return dict(zip(headers, values))

def update_cell(row: int, col_name: str, value):
    ci = col_index(col_name)
    if ci is None:
        # if column doesn't exist, append it to headers and update sheet header row
        headers.append(col_name)
        sheet.update_cell(1, len(headers), col_name)
        ci = len(headers)
    sheet.update_cell(row, ci, value)

# ---------- Email (SMTP) utility ----------
try:
    from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, OTP_TTL_MINUTES
except ImportError:
    # Fallback to environment variables if config.py doesn't exist
    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER")
    SMTP_PASS = os.environ.get("SMTP_PASS")
    OTP_TTL_MINUTES = int(os.environ.get("OTP_TTL_MINUTES", 15))

def send_otp_email(recipient_email: str, otp_code: str, purpose: str = "verification"):
    if not SMTP_USER or not SMTP_PASS:
        logger.warning("SMTP credentials not set; skipping sending email (development mode)")
        return False, "SMTP not configured"
    try:
        msg = EmailMessage()
        
        if purpose == "signup":
            msg["Subject"] = "Verify your BodyCheck account"
            content = f"""Welcome to BodyCheck!

Your verification code is: {otp_code}

This code will expire in {OTP_TTL_MINUTES} minutes.

Please enter this code to complete your account registration.

Best regards,
BodyCheck Team"""
        else:
            msg["Subject"] = "Reset your BodyCheck password"
            content = f"""Password Reset Request

Your OTP code is: {otp_code}

This code will expire in {OTP_TTL_MINUTES} minutes.

If you didn't request this password reset, please ignore this email.

Best regards,
BodyCheck Team"""
        
        msg["From"] = SMTP_USER
        msg["To"] = recipient_email
        msg.set_content(content)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        logger.info(f"Sent {purpose} OTP email to {recipient_email}")
        return True, None
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
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

# ---------- Signup with OTP verification ----------
@app.post("/signup")
async def signup(data: SignupData):
    if sheet is None:
        logger.error("Sheet is None in signup")
        raise HTTPException(status_code=500, detail="Google Sheet not available")
    try:
        # check existing
        all_data = sheet.get_all_records()
        for row in all_data:
            # tolerate header capitalization: check keys for "Email" or "email"
            if (row.get("Email") or row.get("email")) == data.email:
                raise HTTPException(status_code=400, detail="Email already registered")
        
        # generate 6-digit OTP
        otp_code = f"{secrets.randbelow(10**6):06d}"
        expiry = (datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()
        
        # store signup data temporarily with OTP
        password_hash = bcrypt.hash(data.password)
        current_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        
        # Append row with temporary status
        sheet.append_row([data.full_name, data.email, password_hash, current_date, "pending", otp_code, expiry])
        logger.info(f"Signup initiated for: {data.email}")
        
        # send OTP email
        sent, err = send_otp_email(data.email, otp_code, "signup")
        if not sent:
            logger.error(f"Failed to send signup OTP email: {err}")
            return {"message": "Signup initiated. Please check your email for OTP verification."}
        
        return {"message": "Signup initiated. Please check your email for OTP verification."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save data: {e}")

@app.post("/signup-verify")
async def signup_verify(data: SignupVerifyData):
    if sheet is None:
        logger.error("Sheet is None in signup-verify")
        raise HTTPException(status_code=500, detail="Google Sheet not available")
    try:
        row_num = find_row_by_email(data.email)
        if not row_num:
            raise HTTPException(status_code=404, detail="Signup request not found")
        
        record = get_row_record(row_num)
        status = record.get("Status", "")
        
        # If Status column doesn't exist, check if this is a new signup with OTP
        if not status:
            # Check if OTP_Code exists and is not empty
            otp_stored = record.get("OTP_Code", "")
            if otp_stored:
                # This is a pending signup, treat as pending
                status = "pending"
            else:
                # This is an old account without Status column, treat as active
                status = "active"
        
        if status != "pending":
            raise HTTPException(status_code=400, detail="Invalid signup status")
        
        otp_stored = record.get("OTP_Code", "")
        otp_expiry = record.get("OTP_Expiry", "")
        
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
        if str(otp_stored) != str(data.otp):
            raise HTTPException(status_code=401, detail="Invalid OTP")
        
        # activate account
        update_cell(row_num, "Status", "active")
        update_cell(row_num, "OTP_Code", "")
        update_cell(row_num, "OTP_Expiry", "")
        
        logger.info(f"Signup verified successfully for: {data.email}")
        return {"message": "Signup verified successfully! You can now login."}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup verify error: {e}")
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")

# ---------- Login (updated to check for active status) ----------
@app.post("/login")
async def login(data: LoginData):
    logger.info(f"Login attempt for: {data.email}")
    if sheet is None:
        logger.error("Sheet is None in login")
        raise HTTPException(status_code=500, detail="Google Sheet not available")
    try:
        row_num = find_row_by_email(data.email)
        if not row_num:
            logger.warning(f"User not found: {data.email}")
            raise HTTPException(status_code=404, detail="User not found")
        
        record = get_row_record(row_num)
        status = record.get("Status", "")
        
        # Handle missing Status column for backward compatibility
        if not status:
            # Check if OTP_Code exists and is not empty
            otp_stored = record.get("OTP_Code", "")
            if otp_stored:
                # This is a pending signup
                status = "pending"
            else:
                # This is an old account without Status column, treat as active
                status = "active"
        
        # check if account is active
        if status == "pending":
            raise HTTPException(status_code=401, detail="Account not verified. Please check your email for OTP.")
        
        stored_pw = record.get("Password") or record.get("password") or ""
        # Determine if stored_pw is a bcrypt hash
        if stored_pw.startswith("$2b$") or stored_pw.startswith("$2a$"):
            # hashed
            if bcrypt.verify(data.password, stored_pw):
                logger.info(f"Login success (hashed) for {data.email}")
                return {"message": "Login successful","full_name":record.get("Full Name")}
            else:
                logger.warning(f"Invalid password for {data.email}")
                raise HTTPException(status_code=401, detail="Invalid password")
        else:
            # stored as plaintext (migration support)
            if str(stored_pw) == str(data.password):
                # re-hash and update sheet
                new_hash = bcrypt.hash(data.password)
                update_cell(row_num, "Password", new_hash)
                logger.info(f"Login success (plaintext migrated->hashed) for {data.email}")
                return {"message": "Login successful; password migrated"}
            else:
                logger.warning(f"Invalid password (plaintext) for {data.email}")
                raise HTTPException(status_code=401, detail="Invalid password")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {e}")

# ---------- Forgot password (send OTP) ----------

@app.post("/forgot-password")
async def forgot_password(req: ForgotRequest):
    if sheet is None:
        logger.error("Sheet is None in forgot-password")
        raise HTTPException(status_code=500, detail="Google Sheet not available")
    try:
        row_num = find_row_by_email(req.email)
        if not row_num:
            logger.warning(f"Forgot password requested for unknown email: {req.email}")
            # for security, don't reveal whether email exists; still return success
            return {"message": "If that email exists, an OTP has been sent"}
        # generate 6-digit OTP
        otp_code = f"{secrets.randbelow(10**6):06d}"
        expiry = (datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()
        # Ensure columns exist and update
        update_cell(row_num, "OTP_Code", otp_code)
        update_cell(row_num, "OTP_Expiry", expiry)
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
    if sheet is None:
        logger.error("Sheet is None in reset-password")
        raise HTTPException(status_code=500, detail="Google Sheet not available")
    try:
        row_num = find_row_by_email(req.email)
        if not row_num:
            logger.warning(f"Reset attempt for unknown email: {req.email}")
            raise HTTPException(status_code=404, detail="User not found")
        record = get_row_record(row_num)
        otp_stored = record.get("OTP_Code", "")
        otp_expiry = record.get("OTP_Expiry", "")
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
        update_cell(row_num, "Password", new_hash)
        # clear OTP fields
        update_cell(row_num, "OTP_Code", "")
        update_cell(row_num, "OTP_Expiry", "")
        logger.info(f"Password reset successful for: {req.email}")
        return {"message": "Password reset successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"reset-password error: {e}")
        raise HTTPException(status_code=500, detail=f"Reset failed: {e}")

# ---------- Health check ----------
@app.get("/health")
async def health_check():
    try:
        if sheet is None:
            return {"status": "error", "message": "Google Sheet not available"}
        refresh_headers()
        return {"status": "healthy", "headers": headers}
    except Exception as e:
        return {"status": "error", "message": str(e)}


