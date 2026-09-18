import os
import json
import time
import hashlib
import secrets
import sqlite3
import threading
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")

PRODUCTION = os.getenv("NODE_ENV", "development").lower() == "production"
PORT = int(os.getenv("PORT", "3000"))
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemma-4-31b-it").strip()
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openrouter/free").strip()
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "").strip().rstrip("/")
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "").strip()

# Production secrets are required. In local development the server can still start
# without them so the project can be tested before deployment.
if PRODUCTION:
    if not SESSION_SECRET:
        raise RuntimeError("Missing required production secret: SESSION_SECRET")
    if len(SESSION_SECRET) < 32:
        raise RuntimeError("SESSION_SECRET must be at least 32 characters in production.")
    if not DATA_ENCRYPTION_KEY:
        raise RuntimeError("Missing required production secret: DATA_ENCRYPTION_KEY")

DB = BASE / "data" / "personal_ca.sqlite3"
DB.parent.mkdir(parents=True, exist_ok=True)

try:
    from cryptography.fernet import Fernet
except Exception as exc:
    raise RuntimeError("cryptography package is required. Check requirements.txt.") from exc

FERNET = None
if DATA_ENCRYPTION_KEY:
    try:
        FERNET = Fernet(DATA_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("DATA_ENCRYPTION_KEY is not a valid Fernet key.") from exc


def enc(value: str) -> str:
    value = str(value or "")
    return FERNET.encrypt(value.encode("utf-8")).decode("utf-8") if FERNET else value


def dec(value: str) -> str:
    value = str(value or "")
    if not FERNET:
        return value
    try:
        return FERNET.decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        # Do not crash the whole application if an old development value is not encrypted.
        return value


def db():
    conn = sqlite3.connect(DB, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=20000")
    return conn


# IMPORTANT: create the base tables BEFORE running migrations.
# This fixes the previous Render error: "no such table: users".
with db() as conn:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            phone TEXT NOT NULL DEFAULT '',
            picture TEXT NOT NULL DEFAULT '',
            google_verified INTEGER NOT NULL DEFAULT 0,
            email_verified INTEGER NOT NULL DEFAULT 0,
            date_of_birth TEXT NOT NULL DEFAULT '',
            gender TEXT NOT NULL DEFAULT '',
            profile_completed INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            trial_started_at INTEGER,
            trial_ends_at INTEGER,
            paid_until INTEGER,
            last_payment_id TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            event TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id);
        """
    )

# Safe migrations for an older database. The table already exists at this point.
with db() as conn:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    migrations = {
        "phone": "ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''",
        "picture": "ALTER TABLE users ADD COLUMN picture TEXT NOT NULL DEFAULT ''",
        "google_verified": "ALTER TABLE users ADD COLUMN google_verified INTEGER NOT NULL DEFAULT 0",
        "email_verified": "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0",
        "date_of_birth": "ALTER TABLE users ADD COLUMN date_of_birth TEXT NOT NULL DEFAULT ''",
        "gender": "ALTER TABLE users ADD COLUMN gender TEXT NOT NULL DEFAULT ''",
        "profile_completed": "ALTER TABLE users ADD COLUMN profile_completed INTEGER NOT NULL DEFAULT 0",
        "trial_started_at": "ALTER TABLE users ADD COLUMN trial_started_at INTEGER",
        "trial_ends_at": "ALTER TABLE users ADD COLUMN trial_ends_at INTEGER",
        "paid_until": "ALTER TABLE users ADD COLUMN paid_until INTEGER",
        "last_payment_id": "ALTER TABLE users ADD COLUMN last_payment_id TEXT NOT NULL DEFAULT ''",
    }
    for column, sql in migrations.items():
        if column not in existing:
            conn.execute(sql)


app = FastAPI(
    title="Personal CA Backend",
    version="2026.09.14",
    docs_url=None if PRODUCTION else "/docs",
    redoc_url=None if PRODUCTION else "/redoc",
)

# Netlify -> Render needs credentialed CORS because the login session is a cookie.
# If FRONTEND_ORIGIN is empty, same-origin access still works.
allowed_origins = [FRONTEND_ORIGIN] if FRONTEND_ORIGIN else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)

RATE = {}
RATE_LOCK = threading.Lock()


def rate_check(key: str, limit: int, window: int) -> bool:
    now = int(time.time())
    with RATE_LOCK:
        values = [t for t in RATE.get(key, []) if t > now - window]
        if len(values) >= limit:
            return False
        values.append(now)
        RATE[key] = values
    return True


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def new_session(user_id: str) -> str:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
            (token_hash, user_id, now + 7 * 86400, now),
        )
    return token


def get_user(request: Request):
    token = request.cookies.get("pca_session")
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with db() as conn:
        return conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>?",
            (token_hash, now),
        ).fetchone()


def require_user(request: Request):
    user = get_user(request)
    if not user:
        raise HTTPException(401, "Please sign in to Personal CA first.")
    return user


def require_verified(request: Request):
    user = require_user(request)
    if not bool(user["email_verified"]):
        raise HTTPException(403, "This account is not email-verified. Use Google Sign-In or complete the profile before continuing.")
    return user


def require_profile(request: Request):
    # Google accounts are verified by Google. Quick email sign-in intentionally
    # does not send an OTP, so it is treated as a lightweight project account.
    user = require_user(request)
    if not bool(user["profile_completed"]):
        raise HTTPException(403, "Complete your date of birth and gender profile before continuing.")
    return user


def require_active_ai_access(request: Request):
    # This edition is permanently free. Lightweight email sign-in is intentionally
    # allowed without OTP/profile completion so the project can be used immediately.
    return require_user(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin:
            host = request.headers.get("host", "")
            allowed = {f"http://{host}", f"https://{host}"}
            if FRONTEND_ORIGIN:
                allowed.add(FRONTEND_ORIGIN)
            if origin not in allowed:
                return JSONResponse({"error": "Cross-site request blocked."}, status_code=403)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://accounts.google.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://accounts.google.com; "
        "frame-src https://accounts.google.com; "
        "object-src 'none'; base-uri 'self'; form-action 'self';"
    )
    if PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class GoogleBody(BaseModel):
    credential: str = Field(..., min_length=20, max_length=10000)


class EmailBody(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)


class ProfileBody(BaseModel):
    dateOfBirth: str = Field(..., min_length=10, max_length=10)
    gender: str = Field(..., min_length=1, max_length=40)


class AIMessage(BaseModel):
    role: str = Field(..., min_length=1, max_length=20)
    content: str = Field(..., min_length=1, max_length=5000)


class AIRequest(BaseModel):
    messages: list[AIMessage] = Field(..., min_items=1, max_items=20)


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
    return {
        "ok": True,
        "googleConfigured": bool(GOOGLE_CLIENT_ID),
        "aiConfigured": bool(GEMINI_API_KEY or OPENROUTER_API_KEY),
        "paymentsConfigured": False,
        "freeEdition": True,
        "securityMode": "production" if PRODUCTION else "development",
    }


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
        info = id_token.verify_oauth2_token(
            body.credential,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
        if not info.get("sub") or not info.get("email") or info.get("email_verified") is not True:
            raise ValueError("Google account is not verified")

        user_id = str(info["sub"])
        name = str(info.get("name") or "Personal CA user")
        email = str(info["email"])
        picture = str(info.get("picture") or "")
        now = int(time.time())

        with db() as conn:
            old = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if old:
                conn.execute(
                    "UPDATE users SET name=?,email=?,picture=?,google_verified=1,email_verified=1 WHERE id=?",
                    (enc(name), enc(email), enc(picture), user_id),
                )
            else:
                conn.execute(
                    "INSERT INTO users(id,name,email,picture,google_verified,email_verified,created_at) VALUES(?,?,?,?,1,1,?)",
                    (user_id, enc(name), enc(email), enc(picture), now),
                )
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            current = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

        token = new_session(user_id)
        response = JSONResponse(
            {
                "signedIn": True,
                "email": email,
                "name": name,
                "emailVerified": True,
                "profileCompleted": bool(current["profile_completed"]),
                "dateOfBirth": dec(current["date_of_birth"]),
                "gender": dec(current["gender"]),
            }
        )
        # SameSite=None is required for Netlify -> Render credentialed fetches.
        response.set_cookie(
            "pca_session",
            token,
            httponly=True,
            secure=PRODUCTION,
            samesite="none" if PRODUCTION else "lax",
            max_age=7 * 86400,
            path="/",
        )
        return response
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "Google sign-in could not be verified. Please try again.")


@app.post("/api/auth/email")
def auth_email(body: EmailBody, request: Request):
    """Lightweight email sign-in for the school/project edition.

    No OTP or email is sent by design. Therefore this is not identity verification
    and should not be used for a real account system without adding a password,
    magic-link, or another verified authentication method.
    """
    if not rate_check("email:" + client_key(request), 20, 600):
        raise HTTPException(429, "Too many sign-in attempts. Please try again later.")
    email = body.email.strip().lower()
    import re
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "Please enter a valid email address.")

    # Stable project-only account ID. Do not treat this as proof of ownership.
    user_id = "email_" + hashlib.sha256((email + SESSION_SECRET).encode("utf-8")).hexdigest()[:40]
    now = int(time.time())
    with db() as conn:
        old = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if old:
            conn.execute("UPDATE users SET email=?,name=? WHERE id=?", (enc(email), enc(email.split("@")[0] or "Personal CA user"), user_id))
        else:
            conn.execute(
                "INSERT INTO users(id,name,email,picture,google_verified,email_verified,created_at) VALUES(?,?,?,?,0,0,?)",
                (user_id, enc(email.split("@")[0] or "Personal CA user"), enc(email), enc(""), now),
            )
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        current = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    token = new_session(user_id)
    response = JSONResponse({
        "signedIn": True,
        "email": email,
        "name": email.split("@")[0] or "Personal CA user",
        "emailVerified": False,
        "profileCompleted": bool(current["profile_completed"]),
        "dateOfBirth": dec(current["date_of_birth"]),
        "gender": dec(current["gender"]),
        "authMethod": "email_project_signin",
        "notice": "No OTP was sent. This email sign-in is not identity verification."
    })
    response.set_cookie(
        "pca_session", token, httponly=True, secure=PRODUCTION,
        samesite="none" if PRODUCTION else "lax", max_age=7 * 86400, path="/"
    )
    return response


@app.get("/api/auth/me")
def auth_me(request: Request):
    user = get_user(request)
    if not user:
        return {"signedIn": False}
    return {
        "signedIn": True,
        "name": dec(user["name"]),
        "email": dec(user["email"]),
        "picture": dec(user["picture"]),
        "phone": "",
        "emailVerified": bool(user["email_verified"]),
        "profileCompleted": bool(user["profile_completed"]),
        "dateOfBirth": dec(user["date_of_birth"]),
        "gender": dec(user["gender"]),
        "trialEndsAt": None,
        "paidUntil": None,
    }


@app.post("/api/auth/logout")
def logout(request: Request):
    token = request.cookies.get("pca_session")
    if token:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
    response = JSONResponse({"ok": True})
    response.delete_cookie("pca_session", path="/")
    return response


@app.post("/api/profile")
def save_profile(body: ProfileBody, request: Request):
    user = require_verified(request)
    try:
        time.strptime(body.dateOfBirth, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Enter a valid date of birth.")
    gender = body.gender.strip()
    if gender not in {"Female", "Male", "Non-binary", "Prefer not to say"}:
        raise HTTPException(400, "Choose a valid gender option.")
    with db() as conn:
        conn.execute(
            "UPDATE users SET date_of_birth=?,gender=?,profile_completed=1 WHERE id=?",
            (enc(body.dateOfBirth), enc(gender), user["id"]),
        )
        row = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    return {
        "profileCompleted": True,
        "dateOfBirth": dec(row["date_of_birth"]),
        "gender": dec(row["gender"]),
    }


@app.get("/api/profile")
def get_profile(request: Request):
    user = require_verified(request)
    return {
        "profileCompleted": bool(user["profile_completed"]),
        "dateOfBirth": dec(user["date_of_birth"]),
        "gender": dec(user["gender"]),
    }


@app.post("/api/start-trial")
def start_trial(request: Request):
    # Kept for frontend compatibility; the free edition does not expire.
    require_profile(request)
    return {"trialEndsAt": None, "freeEdition": True}


@app.get("/api/trial")
def trial(request: Request):
    require_verified(request)
    return {"started": False, "trialEndsAt": None, "expired": False, "freeEdition": True}


@app.post("/api/logs/event")
def log_event(body: dict, request: Request):
    user = require_verified(request)
    event = str(body.get("event") or "event")[:80]
    detail = str(body.get("detail") or "")[:500]
    with db() as conn:
        conn.execute(
            "INSERT INTO activity_logs(user_id,event,detail,created_at) VALUES(?,?,?,?)",
            (user["id"], event, detail, int(time.time())),
        )
    return {"ok": True}


@app.get("/api/status")
def status(request: Request):
    user = get_user(request)
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    updates_file = BASE / "current_updates.json"
    updates_data = {}
    if updates_file.exists():
        try:
            updates_data = json.loads(updates_file.read_text(encoding="utf-8"))
        except Exception:
            updates_data = {}
    return {
        "logCount": count,
        "rules": {"taxYear": "2026-27", "version": "2026.09.14"},
        "updates": {
            "message": f"Verified source snapshot: {updates_data.get('lastChecked', 'installed package')}",
            "lastChecked": updates_data.get("lastChecked", ""),
        },
        "plan": {"active": True, "name": "Free", "endsAt": None, "trialEndsAt": None, "paidEndsAt": None},
        "user": {"email": dec(user["email"])} if user else None,
    }


@app.post("/api/tax/employee-nps")
def employee_nps(body: NPSRequest, request: Request):
    require_verified(request)
    salary = max(0.0, float(body.salary))
    n1 = max(0.0, float(body.employeeNps1))
    n1b = max(0.0, float(body.employeeNps1b))
    n2 = max(0.0, float(body.employerNps2))
    if not salary:
        raise HTTPException(400, "Annual basic salary plus eligible DA is required.")
    if body.regime == "new":
        d1 = d1b = 0.0
        d2 = min(n2, salary * 0.14)
    else:
        d1 = min(n1, 150000.0)
        d1b = min(n1b, 50000.0)
        rate = 0.14 if body.employerCategory == "govt" else 0.10
        d2 = min(n2, salary * rate)
    rate = 0.14 if body.regime == "new" or body.employerCategory == "govt" else 0.10
    return {
        "taxYear": "2026-27",
        "regime": body.regime,
        "section80CCD1Eligible": d1,
        "section80CCD1BEligible": d1b,
        "section80CCD2Eligible": d2,
        "totalEligibleNpsDeduction": d1 + d1b + d2,
        "caps": {"section80CCD2Rate": rate},
        "source": "Reference calculator; verify applicable current-law treatment before filing.",
    }


def profile_context(user) -> str:
    return (
        "Verified customer profile: date of birth %s; gender %s. "
        "Use these details only when relevant. Do not infer anything beyond supplied facts."
        % (dec(user["date_of_birth"]), dec(user["gender"]))
    )


AI_INSTRUCTIONS = """You are Nivara AI, the educational Indian tax-and-compliance assistant inside Personal CA. Provide careful, factual, educational assistance. When users provide tax facts or structured file information, review income sources, salary, deductions, investments, loans, insurance, NPS, rent/HRA, capital gains, donations, business/professional income, TDS/TCS and compliance considerations. Explain eligibility conditions, limits, evidence needed and uncertainty. Never invent a scheme or promise a refund or specific saving. Distinguish legal deductions from general planning ideas. Flag rules that require verification from current official Indian sources. The Indian Contract Act, 1872 knowledge package is a reference layer, not legal advice. Current tax-year references may change, so encourage verification against official sources. For legal-law questions, route users to the installed official-law coverage catalog and distinguish Income-tax Act 2025 / Rules 2026 from legacy Income-tax Act 1961 / Rules 1962. The 2025 Act contains 536 sections and 16 schedules; the 2026 Rules contain 333 rules and 190 forms. Never invent section text, rule text, form requirements, rates, thresholds, dates or case-law. If exact statutory wording is not installed, say that the official source must be checked. Official source: https://www.incometax.gov.in/iec/foportal/newdownloads/income-tax-act-2025 . Never request or repeat passwords, card PINs, UPI PINs, OTPs, API keys or banking credentials. You are not a Chartered Accountant, lawyer, government official or representative."""


STOCKS_AI_INSTRUCTIONS = """You are Stocks AI, an educational market-research assistant inside Personal CA. Analyze only data actually supplied by the user or a verified data source. Explain business models, fundamentals, valuation concepts, volatility, drawdowns, profitability, leverage, cash flow, dividends, earnings, corporate actions and risks. Clearly label facts versus interpretation and do not invent current prices or live market facts. Do not provide personalized buy/sell/hold decisions, target prices, entry/exit signals, allocations or real-money execution instructions. Paper-trading and learning exercises are allowed. Never request passwords, OTPs, PINs, API keys or brokerage credentials."""


def _extract_openrouter_text(data: dict) -> str:
    choices = data.get("choices") or []
    parts = []
    for choice in choices:
        message = choice.get("message") or {}
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            parts.append(content.strip())
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    value = item.get("text")
                    if isinstance(value, str) and value.strip():
                        parts.append(value.strip())
    return "\n".join(parts).strip()


def openrouter_generate(system_instruction: str, messages: list[dict]) -> str:
    if not OPENROUTER_API_KEY:
        raise HTTPException(
            503,
            "OpenRouter AI is not configured. Add OPENROUTER_API_KEY to Render Environment Variables."
        )

    payload_messages = [{"role": "system", "content": system_instruction}]
    payload_messages.extend(
        {"role": m["role"], "content": m["content"]}
        for m in messages
    )

    payload = json.dumps(
        {
            "model": OPENROUTER_MODEL,
            "messages": payload_messages,
            "temperature": 0.2,
            "max_tokens": 4096,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": FRONTEND_ORIGIN or "https://personal-ca-555.netlify.app",
            "X-Title": "Personal CA",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
            detail = json.loads(body)
            message = (
                detail.get("error", {}).get("message")
                if isinstance(detail.get("error"), dict)
                else None
            )
        except Exception:
            message = None

        safe_message = str(message or "OpenRouter returned an error.")[:300]
        raise HTTPException(
            502,
            f"OpenRouter AI returned HTTP {exc.code}: {safe_message}"
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise HTTPException(
            502,
            "Could not reach OpenRouter AI. Please try again in a moment."
        ) from exc
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(502, "OpenRouter returned an invalid response.") from exc

    result = _extract_openrouter_text(data)
    if not result:
        error = data.get("error")
        if isinstance(error, dict):
            message = str(error.get("message") or "OpenRouter returned no text.")[:300]
            raise HTTPException(502, f"OpenRouter AI error: {message}")
        raise HTTPException(502, "OpenRouter returned no text. Please try again.")

    return result


def gemini_generate(system_instruction: str, contents: list[dict]) -> str:
    if not GEMINI_API_KEY:
        raise HTTPException(
            503,
            "No AI provider is configured. Add OPENROUTER_API_KEY or GEMINI_API_KEY to Render."
        )

    payload = json.dumps(
        {
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "contents": contents,
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
        }
    ).encode("utf-8")

    model = urllib.parse.quote(GEMINI_MODEL, safe="")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "x-goog-api-key": GEMINI_API_KEY,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            502,
            f"Gemini API returned HTTP {exc.code}. Check the Gemini key, model and quota."
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise HTTPException(
            502,
            "Could not reach the Gemini API. Please try again in a moment."
        ) from exc
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(502, "Gemini returned an invalid response.") from exc

    parts = []
    for candidate in data.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            value = part.get("text")
            if value:
                parts.append(value)
    result = "\n".join(parts).strip()
    if not result:
        raise HTTPException(502, "Gemini returned no text. Please try again.")
    return result


def generate_ai(system_instruction: str, messages: list[dict]) -> str:
    # OpenRouter is the primary provider. Gemini remains a safe fallback
    # when a Gemini key is also configured.
    if OPENROUTER_API_KEY:
        try:
            return openrouter_generate(system_instruction, messages)
        except HTTPException:
            if not GEMINI_API_KEY:
                raise

    if GEMINI_API_KEY:
        contents = []
        for message in messages:
            contents.append(
                {
                    "role": "model" if message["role"] == "assistant" else "user",
                    "parts": [{"text": message["content"]}],
                }
            )
        return gemini_generate(system_instruction, contents)

    raise HTTPException(
        503,
        "AI is not configured. Add OPENROUTER_API_KEY to Render Environment Variables."
    )


@app.post("/api/ai")
def ai_chat_alias(body: AIRequest, request: Request):
    return ai_chat(body, request)


@app.post("/api/ai/chat")
def ai_chat(body: AIRequest, request: Request):
    user = require_active_ai_access(request)
    if not rate_check("ai:" + client_key(request), 20, 60):
        raise HTTPException(429, "Too many AI requests. Please wait a moment.")
    contents = [{"role": "user", "parts": [{"text": profile_context(user)}]}]
    for message in body.messages[-12:]:
        role = "model" if message.role == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": message.content[:5000]}]})
    return {"reply": generate_ai(AI_INSTRUCTIONS, [{"role": "user", "content": c["parts"][0]["text"]} for c in contents])}


@app.post("/api/stocks-ai")
def stocks_ai_alias(body: AIRequest, request: Request):
    return stocks_ai_chat(body, request)


@app.post("/api/stocks-ai/research")
def stocks_ai_research(body: StockResearchRequest, request: Request):
    user = require_active_ai_access(request)
    if not rate_check("stocks-research:" + client_key(request), 10, 60):
        raise HTTPException(429, "Too many Stocks AI research requests. Please wait a moment.")
    symbol = body.symbol.strip()[:40]
    if not symbol or any(ch in symbol for ch in "\r\n\""):
        raise HTTPException(400, "Enter a valid stock symbol or company name.")
    prompt = (
        f"Provide an educational stock-study brief for: {symbol}. "
        "There is no verified live market-data feed in this endpoint. Do not invent current price, market cap, today's change or latest earnings as live facts. "
        "Explain business model, fundamentals to study, valuation concepts, major risks, governance questions and what data a learner should verify next. "
        "Do not give buy, sell, hold, entry, exit, target-price, allocation or real-money trading instructions."
    )
    contents = [
        {"role": "user", "parts": [{"text": profile_context(user)}]},
        {"role": "user", "parts": [{"text": prompt}]},
    ]
    return {
        "symbol": symbol,
        "source": "Google Gemini (educational knowledge; no live quote feed)",
        "retrievedAt": int(time.time()),
        "reply": generate_ai(STOCKS_AI_INSTRUCTIONS, [{"role": "user", "content": c["parts"][0]["text"]} for c in contents]),
    }


@app.post("/api/stocks-ai/chat")
def stocks_ai_chat(body: AIRequest, request: Request):
    user = require_active_ai_access(request)
    if not rate_check("stocks-ai:" + client_key(request), 15, 60):
        raise HTTPException(429, "Too many Stocks AI requests. Please wait a moment.")
    contents = [{"role": "user", "parts": [{"text": profile_context(user)}]}]
    for message in body.messages[-12:]:
        role = "model" if message.role == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": message.content[:5000]}]})
    return {"reply": gemini_generate(STOCKS_AI_INSTRUCTIONS, contents)}


@app.get("/api/legal/income-tax-coverage")
def income_tax_coverage():
    path = BASE / "legal_knowledge" / "income_tax_law_catalog.json"
    if not path.exists():
        raise HTTPException(404, "Income-tax law coverage catalog not found.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(500, "Income-tax law coverage catalog could not be read.") from exc


@app.get("/api/legal/contract-law")
def contract_law():
    path = BASE / "legal_knowledge" / "indian_contract_act.json"
    if not path.exists():
        raise HTTPException(404, "Contract law knowledge package not found.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(500, "Contract law knowledge package could not be read.") from exc


@app.get("/api/updates")
def updates():
    path = BASE / "current_updates.json"
    if not path.exists():
        return {"items": [], "lastChecked": ""}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"items": [], "lastChecked": ""}


@app.get("/")
def home():
    path = BASE / "index.html"
    if not path.exists():
        raise HTTPException(404, "Website file not found.")
    return FileResponse(path)


@app.get("/{path:path}")
def static_files(path: str):
    target = (BASE / path).resolve()
    if BASE not in target.parents and target != BASE:
        raise HTTPException(404)
    if target.is_file():
        return FileResponse(target)
    index = BASE / "index.html"
    if index.exists():
        return FileResponse(index)
    raise HTTPException(404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)
