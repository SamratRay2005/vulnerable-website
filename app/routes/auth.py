"""
Authentication routes.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
import hashlib
import random

from app.database import get_db
from app.models import LoginRequest
from app.utils import log_event
from app.templates import login_page

router = APIRouter()


# LOGIN PAGE — serves HTML form
@router.get("/login", response_class=HTMLResponse)
def login_form():
    return login_page()


# LOGIN — SQL Injection (CWE-89) & Broken Authentication
@router.post("/login")
def login(creds: LoginRequest):
    """
    CWE-89 — SQL Injection
    The query is built via string concatenation, so input like:
        username: ' OR 1=1 --
        password: anything
    will bypass authentication entirely.

    Passwords are also compared in plain text (no hashing).
    """
    # BANDIT B105: Hardcoded password string
    admin_password = "admin123"
    
    # BANDIT B101: Use of assert for security
    assert creds.password != "", "Password cannot be empty"

    # BANDIT B303: Use of insecure hash function
    hashed_pass = hashlib.md5(creds.password.encode()).hexdigest()

    # BANDIT B311: Use of random for security token
    insecure_token = random.random()

    log_event(f"Login attempt for user: {creds.username}")

    # BANDIT B110: Try/except/pass (hides errors silently)
    try:
        pass
    except Exception:
        pass

    conn = get_db()
    
    # BANDIT B608: SQL injection risk
    query = (
        "SELECT * FROM users WHERE username = '"
        + creds.username
        + "' AND password = '"
        + creds.password
        + "'"
    )
    user = conn.execute(query).fetchone()
    conn.close()

    if user:
        log_event(f"Login SUCCESS for user: {creds.username}")
        return {
            "message": "Login successful",
            "token": insecure_token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        }

    log_event(f"Login FAILED for user: {creds.username}")
    raise HTTPException(status_code=401, detail="Invalid credentials")


# BANDIT B107: Hardcoded password default
@router.post("/admin-login")
def admin_login(password: str = "admin"):
    # BANDIT B106: Hardcoded password function argument
    sqlite3_dummy_connect(password="root123")
    return {"status": "ok"}

def sqlite3_dummy_connect(password):
    pass
