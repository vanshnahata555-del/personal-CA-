import os, json, time, hmac, hashlib, secrets, sqlite3, smtplib, ssl, threading, urllib.request, urllib.error, base64, urllib.parse
from pathlib import Path
from email.message import EmailMessage
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")

PRODUCTION = os.getenv("NODE_ENV", "development").lower() == "production"
PORT = int(os.getenv("PORT", "3000"))
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "").rstrip("/")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID", "")
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "")

if PRODUCTION:
    required = {"SESSION_SECRET": SESSION_SECRET, "DATA_ENCRYPTION_KEY": DATA_ENCRYPTION_KEY}
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise RuntimeError("Missing required production secrets: " + ", ".join(missing))
    if len(SESSION_SECRET) < 32:
        raise RuntimeError("SESSION_SECRET must be at least 32 characters in production.")

DB = BASE / "data" / "personal_ca.sqlite3"
DB.parent.mkdir(parents=True, exist_ok=True)

# Fernet is optional only for development; production requires it.
try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

if DATA_ENCRYPTION_KEY:
    if Fernet is None:
        raise RuntimeError("cryptography package is required when DATA_ENCRYPTION_KEY is set.")
    try:
        FERNET = Fernet(DATA_ENCRYPTION_KEY.encode())
    except Exception as e:
        raise RuntimeError("DATA_ENCRYPTION_KEY is not a valid Fernet key.") from e
else:
    FERNET = None


def enc(value: str) -> str:
    value = str(value or "")
    if not FERNET:
        return value
    return FERNET.encrypt(value.encode()).decode()


def dec(value: str) -> str:
    if not FERNET:
        return value
    try:
        return FERNET.decrypt(value.encode()).decode()
    except Exception:
        return ""


def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


# Safe schema migration for existing installations.
with db() as c:
    cols = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
    if "phone" not in cols: c.execute("ALTER TABLE users ADD COLUMN phone TEXT DEFAULT ''")
    if "phone_verified" not in cols: c.execute("ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0")
    if "date_of_birth" not in cols: c.execute("ALTER TABLE users ADD COLUMN date_of_birth TEXT DEFAULT ''")
    if "gender" not in cols: c.execute("ALTER TABLE users ADD COLUMN gender TEXT DEFAULT ''")
    if "profile_completed" not in cols: c.execute("ALTER TABLE users ADD COLUMN profile_completed INTEGER NOT NULL DEFAULT 0")
    if "paid_until" not in cols: c.execute("ALTER TABLE users ADD COLUMN paid_until INTEGER")
    if "last_payment_id" not in cols: c.execute("ALTER TABLE users ADD COLUMN last_payment_id TEXT DEFAULT ''")


with db() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL DEFAULT '',
      phone TEXT DEFAULT '',
      picture TEXT DEFAULT '',
      google_verified INTEGER NOT NULL DEFAULT 0,
      phone_verified INTEGER NOT NULL DEFAULT 0,
      email_verified INTEGER NOT NULL DEFAULT 0,
      date_of_birth TEXT DEFAULT '',
      gender TEXT DEFAULT '',
      profile_completed INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      trial_started_at INTEGER,
      trial_ends_at INTEGER,
      paid_until INTEGER,
      last_payment_id TEXT DEFAULT '',
      otp_hash TEXT,
      otp_expires_at INTEGER,
      otp_sent_at INTEGER,
      otp_attempts INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      event TEXT NOT NULL,
      detail TEXT DEFAULT '',
      created_at INTEGER NOT NULL
    );
    """)

app = FastAPI(docs_url=None if PRODUCTION else "/docs", redoc_url=None if PRODUCTION else "/redoc")

# Same-origin app. CORS is intentionally disabled for arbitrary origins.
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN else [], allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

RATE = {}
RATE_LOCK = threading.Lock()

def rate_check(key: str, limit: int, window: int):
    now = int(time.time())
    with RATE_LOCK:
        arr = [t for t in RATE.get(key, []) if t > now - window]
        if len(arr) >= limit:
            return False
        arr.append(now)
        RATE[key] = arr
    return True


def client_key(request: Request):
    # Do not trust arbitrary forwarded IP headers. The platform proxy can be configured separately.
    return request.client.host if request.client else "unknown"


def new_session(user_id: str):
    token = secrets.token_urlsafe(48)
    th = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    with db() as c:
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        c.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)", (th, user_id, now + 7*86400, now))
    return token


def get_user(request: Request):
    token = request.cookies.get("pca_session")
    if not token:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    with db() as c:
        row = c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?", (th, now)).fetchone()
    return row


def require_user(request: Request):
    u = get_user(request)
    if not u:
        raise HTTPException(401, "Please sign in with Google first.")
    return u


def require_verified(request: Request):
    u = require_user(request)
    if not u["email_verified"]:
        raise HTTPException(403, "Please sign in with a verified Google account before continuing.")
    return u

def require_profile(request: Request):
    u = require_verified(request)
    if not u["profile_completed"]:
        raise HTTPException(403, "Complete your date of birth and gender profile before continuing.")
    return u

def require_active_ai_access(request: Request):
    # Personal CA Free edition: AI access is available after Google sign-in
    # and completion of the basic profile. No subscription or payment is required.
    return require_profile(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Reject cross-site state-changing browser requests. This complements SameSite cookies.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        host = request.headers.get("host", "")
        if origin:
            allowed = {f"http://{host}", f"https://{host}"}
            if FRONTEND_ORIGIN: allowed.add(FRONTEND_ORIGIN)
            if origin not in allowed:
                return JSONResponse({"error": "Cross-site request blocked."}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://accounts.google.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://accounts.google.com https://challenges.cloudflare.com; frame-src https://accounts.google.com https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self';"
    if PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class PhoneBody(BaseModel):
    phone: str = Field(..., min_length=8, max_length=20)

class PhoneVerifyBody(BaseModel):
    phone: str = Field(..., min_length=8, max_length=20)
    code: str = Field(..., min_length=4, max_length=8)

class GoogleBody(BaseModel):
    credential: str = Field(min_length=20, max_length=10000)

class OTPBody(BaseModel):
    code: str = Field(regex=r"^[0-9]{6}$")

class ProfileBody(BaseModel):
    dateOfBirth: str = Field(..., min_length=10, max_length=10)
    gender: str = Field(..., min_length=1, max_length=40)

class AIMessage(BaseModel):
    role: str
    content: str = Field(min_length=1, max_length=5000)

class AIRequest(BaseModel):
    messages: list[AIMessage] = Field(min_length=1, max_length=20)

class StockResearchRequest(BaseModel):
    symbol: str = Field(..., min_length=1, max_length=40)

class NPSRequest(BaseModel):
    regime: str = "new"
    salary: float = 0
    employeeNps1: float = 0
    employeeNps1b: float = 0
    employerNps2: float = 0
    employerCategory: str = "govt"


@app.get("/api/health")
def health():
    return {"ok": True, "googleConfigured": bool(GOOGLE_CLIENT_ID), "aiConfigured": bool(GEMINI_API_KEY), "emailOtpConfigured": bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and SMTP_FROM), "phoneOtpConfigured": bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_VERIFY_SERVICE_SID), "paymentsConfigured": False, "freeEdition": True, "securityMode": "production" if PRODUCTION else "development"}

@app.get("/api/config")
def config():
    return {"googleClientId": GOOGLE_CLIENT_ID or None}

@app.post("/api/auth/google")
def auth_google(body: GoogleBody, request: Request):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(503, "Google Sign-In is not configured on the server.")
    if not rate_check("google:" + client_key(request), 20, 600):
        raise HTTPException(429, "Too many sign-in attempts. Please try again later.")
    try:
        info = id_token.verify_oauth2_token(body.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
        if not info.get("sub") or not info.get("email") or info.get("email_verified") is not True:
            raise ValueError("unverified account")
        user_id = str(info["sub"])
        now = int(time.time())
        name, email, picture = str(info.get("name") or "Personal CA user"), str(info["email"]), str(info.get("picture") or "")
        with db() as c:
            old = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            c.execute("""INSERT INTO users(id,name,email,picture,google_verified,email_verified,created_at)
                         VALUES(?,?,?,?,1,1,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,email=excluded.email,picture=excluded.picture,google_verified=1,email_verified=1""",
                      (user_id, enc(name), enc(email), enc(picture), old["created_at"] if old else now))
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        token = new_session(user_id)
        response = JSONResponse({"signedIn": True, "email": email, "name": name, "emailVerified": True, "profileCompleted": bool(old["profile_completed"]) if old else False, "dateOfBirth": dec(old["date_of_birth"]) if old else "", "gender": dec(old["gender"]) if old else ""})
        response.set_cookie("pca_session", token, httponly=True, secure=PRODUCTION, samesite="lax", max_age=7*86400, path="/")
        return response
    except Exception:
        raise HTTPException(401, "Google sign-in could not be verified. Please try again.")

@app.get("/api/auth/me")
def auth_me(request: Request):
    u = get_user(request)
    if not u: return {"signedIn": False}
    return {"signedIn": True, "name": dec(u["name"]), "email": dec(u["email"]), "picture": dec(u["picture"]), "phone": dec(u["phone"]), "emailVerified": bool(u["email_verified"]), "profileCompleted": bool(u["profile_completed"]), "dateOfBirth": dec(u["date_of_birth"]), "gender": dec(u["gender"]), "trialEndsAt": u["trial_ends_at"] and time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(u["trial_ends_at"])), "paidUntil": u["paid_until"] and time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(u["paid_until"]))}

@app.post("/api/auth/logout")
def logout(request: Request):
    token = request.cookies.get("pca_session")
    if token:
        th = hashlib.sha256(token.encode()).hexdigest()
        with db() as c: c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
    response = JSONResponse({"ok": True})
    response.delete_cookie("pca_session", path="/")
    return response


def send_otp(email: str, code: str):
    msg = EmailMessage()
    msg["Subject"] = "Your Personal CA verification code"
    msg["From"] = SMTP_FROM
    msg["To"] = email
    msg.set_content(f"Your Personal CA verification code is {code}. It expires in 10 minutes. If you did not request this, ignore this email.")
    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=20) as server:
            server.login(SMTP_USER, SMTP_PASSWORD); server.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls(context=context); server.login(SMTP_USER, SMTP_PASSWORD); server.send_message(msg)

def normalize_phone(phone: str) -> str:
    value = phone.strip().replace(" ", "").replace("-", "")
    if not value.startswith("+") or not value[1:].isdigit():
        raise HTTPException(400, "Enter a phone number in international format, for example +91XXXXXXXXXX.")
    return value[:20]

def twilio_verify(action: str, phone: str, code: str | None = None):
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_VERIFY_SERVICE_SID):
        raise HTTPException(503, "Phone OTP sign-in is not configured. Add the Twilio Verify settings on the server.")
    url = f"https://verify.twilio.com/v2/Services/{urllib.parse.quote(TWILIO_VERIFY_SERVICE_SID, safe='')}/{action}"
    fields = {"To": phone, "Channel": "sms"} if action == "Verifications" else {"To": phone, "Code": code or ""}
    data = urllib.parse.urlencode(fields).encode()
    auth = base64.b64encode(f"{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}".encode()).decode()
    req = urllib.request.Request(url, data=data, headers={"Authorization": "Basic " + auth, "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError):
        raise HTTPException(502, "Phone verification service is temporarily unavailable.")

@app.post("/api/auth/phone/send")
def phone_send(body: PhoneBody, request: Request):
    phone = normalize_phone(body.phone)
    if not rate_check("phone-send:" + client_key(request), 3, 600): raise HTTPException(429, "Too many SMS requests. Please wait before trying again.")
    user_id = "phone:" + hashlib.sha256(phone.encode()).hexdigest()
    now = int(time.time())
    with db() as c:
        c.execute("INSERT INTO users(id,name,email,phone,phone_verified,email_verified,created_at) VALUES(?,?,?,?,0,1,?) ON CONFLICT(id) DO UPDATE SET phone=excluded.phone", (user_id, "Phone user", "", enc(phone), now))
    twilio_verify("Verifications", phone)
    return {"sent": True, "phone": phone[:4] + "••••••" + phone[-2:]}

@app.post("/api/auth/phone/verify")
def phone_verify(body: PhoneVerifyBody, request: Request):
    phone = normalize_phone(body.phone)
    if not rate_check("phone-verify:" + client_key(request), 8, 600): raise HTTPException(429, "Too many verification attempts. Please try again later.")
    result = twilio_verify("VerificationCheck", phone, body.code)
    if result.get("status") != "approved": raise HTTPException(400, "Incorrect or expired phone verification code.")
    user_id = "phone:" + hashlib.sha256(phone.encode()).hexdigest()
    now = int(time.time())
    with db() as c:
        c.execute("UPDATE users SET phone_verified=1,email_verified=1 WHERE id=?", (user_id,))
        u=c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    token=new_session(user_id)
    response=JSONResponse({"signedIn":True,"name":dec(u["name"]),"email":"","phone":phone,"emailVerified":True,"profileCompleted":bool(u["profile_completed"]),"dateOfBirth":dec(u["date_of_birth"]),"gender":dec(u["gender"]),"trialEndsAt":u["trial_ends_at"] and time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(u["trial_ends_at"]))})
    response.set_cookie("pca_session", token, httponly=True, secure=PRODUCTION, samesite="lax", max_age=7*86400, path="/")
    return response

@app.post("/api/email-otp/send")
def otp_send(request: Request):
    u = require_user(request)
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD and SMTP_FROM): raise HTTPException(503, "Email OTP is not configured. Add SMTP settings on the server.")
    if not rate_check("otp-send:" + client_key(request), 5, 600): raise HTTPException(429, "Too many OTP requests. Please wait before trying again.")
    now = int(time.time())
    if u["otp_sent_at"] and now - u["otp_sent_at"] < 45: raise HTTPException(429, "Please wait 45 seconds before requesting another OTP.")
    code = f"{secrets.randbelow(900000)+100000:06d}"
    digest = hashlib.sha256(code.encode()).hexdigest()
    email = dec(u["email"])
    with db() as c: c.execute("UPDATE users SET otp_hash=?,otp_expires_at=?,otp_sent_at=?,otp_attempts=0 WHERE id=?", (digest, now+600, now, u["id"]))
    try:
        send_otp(email, code)
    except Exception:
        with db() as c: c.execute("UPDATE users SET otp_hash=NULL,otp_expires_at=NULL WHERE id=?", (u["id"],))
        raise HTTPException(500, "The verification email could not be sent. Check the server email settings.")
    masked = email[:2] + "••••" + email[email.find("@"):]
    return {"sent": True, "email": masked}

@app.post("/api/email-otp/verify")
def otp_verify(body: OTPBody, request: Request):
    u = require_user(request)
    if not rate_check("otp-verify:" + client_key(request), 10, 600): raise HTTPException(429, "Too many OTP attempts. Please try again later.")
    now = int(time.time())
    if not u["otp_hash"] or now > int(u["otp_expires_at"] or 0): raise HTTPException(400, "That OTP has expired. Request a new one.")
    if int(u["otp_attempts"] or 0) >= 5: raise HTTPException(429, "Too many incorrect attempts. Request a new OTP.")
    digest = hashlib.sha256(body.code.encode()).hexdigest()
    with db() as c:
        c.execute("UPDATE users SET otp_attempts=otp_attempts+1 WHERE id=?", (u["id"],))
        if not hmac.compare_digest(digest, u["otp_hash"]): raise HTTPException(400, "Incorrect OTP.")
        c.execute("UPDATE users SET email_verified=1,otp_hash=NULL,otp_expires_at=NULL,otp_sent_at=NULL,otp_attempts=0 WHERE id=?", (u["id"],))
    return {"verified": True, "email": dec(u["email"]), "name": dec(u["name"])}

@app.post("/api/profile")
def save_profile(body: ProfileBody, request: Request):
    u=require_verified(request)
    try:
        dob=time.strptime(body.dateOfBirth, "%Y-%m-%d")
        if time.mktime(dob) > time.time(): raise ValueError()
    except ValueError:
        raise HTTPException(400, "Enter a valid date of birth.")
    gender=body.gender.strip()
    if gender not in {"Female","Male","Non-binary","Prefer not to say"}:
        raise HTTPException(400, "Choose a valid gender option.")
    with db() as c:
        c.execute("UPDATE users SET date_of_birth=?,gender=?,profile_completed=1 WHERE id=?", (enc(body.dateOfBirth), enc(gender), u["id"]))
        row=c.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    return {"profileCompleted":True,"dateOfBirth":dec(row["date_of_birth"]),"gender":dec(row["gender"])}

@app.get("/api/profile")
def get_profile(request: Request):
    u=require_verified(request)
    return {"profileCompleted":bool(u["profile_completed"]),"dateOfBirth":dec(u["date_of_birth"]),"gender":dec(u["gender"])}

@app.post("/api/start-trial")
def start_trial(request: Request):
    u = require_profile(request); now = int(time.time())
    if not u["trial_started_at"]:
        with db() as c: c.execute("UPDATE users SET trial_started_at=?,trial_ends_at=? WHERE id=?", (now, now+3*86400, u["id"]))
        end = now+3*86400
    else: end = u["trial_ends_at"]
    return {"trialEndsAt": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(end))}

@app.get("/api/trial")
def trial(request: Request):
    u = require_verified(request); end = u["trial_ends_at"]
    return {"started": bool(u["trial_started_at"]), "trialEndsAt": end and time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(end)), "expired": bool(end and int(time.time()) >= end)}

@app.post("/api/logs/event")
def log_event(body: dict, request: Request):
    u=require_verified(request)
    event=str(body.get("event") or "event")[:80]
    detail=str(body.get("detail") or "")[:500]
    with db() as c:
        c.execute("INSERT INTO activity_logs(user_id,event,detail,created_at) VALUES(?,?,?,?)", (u["id"],event,detail,int(time.time())))
    return {"ok":True}

@app.get("/api/status")
def status(request: Request):
    u=get_user(request)
    with db() as c:
        count=c.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    p=BASE/"current_updates.json"
    upd=json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    return {"logCount":count,"rules":{"taxYear":"2026-27","version":"2026.09.10"},"updates":{"message":f"Verified source snapshot: {upd.get('lastChecked','installed package')}","lastChecked":upd.get("lastChecked","")},"plan":{"active":True,"name":"Free","endsAt":None,"trialEndsAt":None,"paidEndsAt":None},"user":{"email":dec(u["email"])} if u else None}

@app.post("/api/tax/employee-nps")
def employee_nps(body: NPSRequest, request: Request):
    require_verified(request)
    s,n1,n1b,n2 = max(0,body.salary),max(0,body.employeeNps1),max(0,body.employeeNps1b),max(0,body.employerNps2)
    if not s: raise HTTPException(400,"Annual basic salary plus eligible DA is required.")
    if body.regime == "new": d1=d1b=0; d2=min(n2,s*0.14)
    else:
        d1=min(n1,150000); d1b=min(n1b,50000); d2=min(n2,s*(0.14 if body.employerCategory=="govt" else 0.10))
    return {"taxYear":"2026-27","regime":body.regime,"section80CCD1Eligible":d1,"section80CCD1BEligible":d1b,"section80CCD2Eligible":d2,"totalEligibleNpsDeduction":d1+d1b+d2,"caps":{"section80CCD2Rate":0.14 if body.regime=="new" else (0.14 if body.employerCategory=="govt" else 0.10)},"source":"Income Tax Department AY 2026-27 guidance and CBDT ITR validation rules"}

def profile_context(u):
    return "Verified customer profile: date of birth %s; gender %s. Use these details only when relevant to tax eligibility/calculation. Do not infer anything beyond the supplied profile." % (dec(u["date_of_birth"]), dec(u["gender"]))

AI_INSTRUCTIONS = """You are Nivara AI, the educational Indian tax-and-compliance intelligence assistant inside Personal CA for Indian users. Think like a very careful senior tax analyst: when the user provides a financial/tax file or structured facts, systematically scan income sources, salary components, deductions, investments, loans, insurance, NPS, rent/HRA, capital gains, donations, business/professional income, TDS/TCS, and other relevant fields for lawful tax-saving opportunities, missed deductions, regime differences, compliance risks, and missing documents. Explain WHY an item may reduce tax, the eligibility conditions, limits, and what evidence is needed. Never invent a scheme or claim that a customer is eligible without enough facts. Distinguish a genuine legal deduction/exemption from a mere tax-planning idea. Do not promise a refund or a specific saving. Prioritize current official Indian sources and clearly flag when a rule needs verification. The product also includes a legal-reference knowledge package for the Indian Contract Act, 1872; treat it as a reference layer, not as a substitute for the official consolidated statute or legal advice. Recognize that the Indian Contract Act, 1872 remains the principal central contract statute listed by India Code, with historical provisions repealed or moved into related statutes such as the Sale of Goods Act, 1930 and Indian Partnership Act, 1932. Recognize Tax Year 2026-27 and the transition to the Income-tax Act, 2025 and Income-tax Rules, 2026; older years may use earlier law and transitional rules. When file data is incomplete, state exactly what is missing and ask only for the minimum additional information. Never request or repeat passwords, card PINs, UPI PINs, OTPs, API keys, or banking credentials. For employee NPS, distinguish the applicable current-law treatment of employee and employer contributions and do not show an interactive 80CCD calculator before the analysis/review stage. Use deterministic calculator results when supplied; AI should explain them, not override them. You are not a Chartered Accountant, lawyer, government official, or representative."""

@app.post("/api/ai/chat")
def ai_chat(body: AIRequest, request: Request):
    u=require_active_ai_access(request)
    if not rate_check("ai:"+client_key(request), 20, 60): raise HTTPException(429,"Too many AI requests. Please wait a moment.")
    if not GEMINI_API_KEY: raise HTTPException(503,"Your CA AI is not configured yet. Add GEMINI_API_KEY to the server environment.")
    contents=[]
    contents.append({"role":"user","parts":[{"text":profile_context(u)}]})
    for m in body.messages[-12:]:
        contents.append({"role":"model" if m.role=="assistant" else "user","parts":[{"text":m.content[:5000]}]})
    try:
        payload = json.dumps({
            "systemInstruction": {"parts": [{"text": AI_INSTRUCTIONS}]},
            "contents": contents,
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096}
        }).encode("utf-8")
        url = "https://generativelanguage.googleapis.com/v1beta/models/" + urllib.parse.quote(GEMINI_MODEL, safe="") + ":generateContent"
        req = urllib.request.Request(
            url, data=payload, headers={
                "x-goog-api-key": GEMINI_API_KEY,
                "Content-Type": "application/json"
            }, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        parts=[]
        for cand in data.get("candidates", []):
            for part in cand.get("content", {}).get("parts", []):
                if part.get("text"): parts.append(part["text"])
        text="\n".join(parts).strip()
        if not text: raise RuntimeError("empty")
        return {"reply": text}
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError, RuntimeError):
        raise HTTPException(502,"Your CA AI could not complete that request right now. Please try again in a moment.")
    except Exception:
        raise HTTPException(502,"Your CA AI could not complete that request right now. Please try again in a moment.")

STOCKS_AI_INSTRUCTIONS = """You are Stocks AI, a high-quality educational market-research assistant inside Personal CA. Analyze only market data supplied by the server or by the user. You can explain price/volume history, trend structure, volatility, drawdowns, valuation metrics, profitability, leverage, cash flow, dividends, earnings, corporate actions, and other fundamental/technical concepts. When live or recent data is supplied, clearly state the timestamp and data source, separate facts from interpretation, and explain what changed versus earlier observations. You may compare companies factually and identify risks or unanswered questions. Do NOT tell a minor which security to buy, sell, hold, accumulate, exit, or when to enter/exit; do NOT give target prices, personalized allocations, trading signals, or instructions for real-money execution. If the user says they already own a security, you may help them understand the position, risk, historical performance, and what information an investor should review before discussing it with a parent/guardian or qualified professional, but you must not make the buy/sell decision for them. You may support paper-trading/learning exercises. Never request passwords, OTPs, PINs, API keys, or brokerage credentials. Securities can lose money. Current exchange rules, fees, corporate actions, and platform interfaces must be verified from official sources."""

@app.post("/api/stocks-ai/research")
def stocks_ai_research(body: StockResearchRequest, request: Request):
    u=require_active_ai_access(request)
    if not rate_check("stocks-research:"+client_key(request), 10, 60):
        raise HTTPException(429,"Too many Stocks AI research requests. Please wait a moment.")
    if not GEMINI_API_KEY:
        raise HTTPException(503,"Stocks AI is not configured yet. Add GEMINI_API_KEY to the server environment.")
    symbol=body.symbol.strip()[:40]
    if not symbol or any(ch in symbol for ch in "\r\n\""):
        raise HTTPException(400,"Enter a valid stock symbol or company name.")
    prompt=f"""Provide an educational stock-study brief for the supplied symbol/company: {symbol}.

Important: you do NOT have a verified live market-data feed in this endpoint. Do not invent or present current price, current market cap, today's change, latest earnings, or other time-sensitive facts as live facts. If you mention facts that may have changed, label them as knowledge-based and recommend checking the company's latest official filings/exchange disclosures. Explain business model, key fundamentals to study, valuation concepts, major risks, governance questions, and what data a learner should verify next. Do not give buy, sell, hold, entry, exit, target-price, allocation, or real-money trading instructions. This is educational research for a minor and may support paper-trading exercises only."""
    contents=[{"role":"user","parts":[{"text":profile_context(u)}]},{"role":"user","parts":[{"text":prompt}]}]
    try:
        payload=json.dumps({"systemInstruction":{"parts":[{"text":STOCKS_AI_INSTRUCTIONS}]},"contents":contents,"generationConfig":{"temperature":0.2,"maxOutputTokens":4096}}).encode("utf-8")
        url="https://generativelanguage.googleapis.com/v1beta/models/"+urllib.parse.quote(GEMINI_MODEL,safe="")+":generateContent"
        req=urllib.request.Request(url,data=payload,headers={"x-goog-api-key":GEMINI_API_KEY,"Content-Type":"application/json"},method="POST")
        with urllib.request.urlopen(req,timeout=60) as resp: data=json.loads(resp.read().decode("utf-8"))
        parts=[]
        for cand in data.get("candidates",[]):
            for part in cand.get("content",{}).get("parts",[]):
                if part.get("text"): parts.append(part["text"])
        text="\n".join(parts).strip()
        if not text: raise RuntimeError("empty")
        return {"symbol":symbol,"source":"Google Gemini (knowledge-based; no live quote feed)","retrievedAt":int(time.time()),"reply":text}
    except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError,ValueError,RuntimeError):
        raise HTTPException(502,"Stocks AI could not complete the Gemini research request right now.")
    except Exception:
        raise HTTPException(502,"Stocks AI could not complete the Gemini research request right now.")

@app.post("/api/stocks-ai/chat")
def stocks_ai_chat(body: AIRequest, request: Request):
    u=require_active_ai_access(request)
    if not rate_check("stocks-ai:"+client_key(request), 15, 60): raise HTTPException(429,"Too many Stocks AI requests. Please wait a moment.")
    if not GEMINI_API_KEY: raise HTTPException(503,"Stocks AI is not configured yet. Add GEMINI_API_KEY to the server environment.")
    contents=[]
    contents.append({"role":"user","parts":[{"text":profile_context(u)}]})
    for m in body.messages[-12:]:
        contents.append({"role":"model" if m.role=="assistant" else "user","parts":[{"text":m.content[:5000]}]})
    try:
        payload=json.dumps({
            "systemInstruction": {"parts": [{"text": STOCKS_AI_INSTRUCTIONS}]},
            "contents": contents,
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096}
        }).encode("utf-8")
        url="https://generativelanguage.googleapis.com/v1beta/models/" + urllib.parse.quote(GEMINI_MODEL, safe="") + ":generateContent"
        req=urllib.request.Request(url,data=payload,headers={"x-goog-api-key":GEMINI_API_KEY,"Content-Type":"application/json"},method="POST")
        with urllib.request.urlopen(req,timeout=60) as resp: data=json.loads(resp.read().decode("utf-8"))
        parts=[]
        for cand in data.get("candidates",[]):
            for part in cand.get("content",{}).get("parts",[]):
                if part.get("text"): parts.append(part["text"])
        text="\n".join(parts).strip()
        if not text: raise RuntimeError("empty")
        return {"reply":text}
    except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError,ValueError,RuntimeError):
        raise HTTPException(502,"Stocks AI could not complete that request right now. Please try again in a moment.")
    except Exception:
        raise HTTPException(502,"Stocks AI could not complete that request right now. Please try again in a moment.")


@app.get("/api/legal/contract-law")
def contract_law():
    p = BASE / "legal_knowledge" / "indian_contract_act.json"
    if not p.exists():
        raise HTTPException(404, "Contract law knowledge package not found.")
    return json.loads(p.read_text(encoding="utf-8"))

@app.get("/api/updates")
def updates():
    p=BASE/"current_updates.json"
    if not p.exists(): return {"items":[],"lastChecked":""}
    return json.loads(p.read_text(encoding="utf-8"))

# Static site is served by the same origin; API keys are never sent to the browser.
@app.get("/")
def home(): return FileResponse(BASE/"index.html")

@app.get("/{path:path}")
def static_files(path: str):
    target=(BASE/path).resolve()
    if BASE not in target.parents and target != BASE: raise HTTPException(404)
    if target.is_file(): return FileResponse(target)
    return FileResponse(BASE/"index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=PORT, reload=False)
