"""
Profile and role management routes.
"""

from fastapi import APIRouter, HTTPException, Body
from fastapi.responses import HTMLResponse
from django.utils.safestring import mark_safe

from app.database import get_db
from app.models import RoleUpdate
from app.utils import log_event
from app.templates import profile_page, update_role_page

router = APIRouter()


# PROFILE LOOKUP PAGE — serves HTML form
@router.get("/profile", response_class=HTMLResponse)
def profile_form():
    return profile_page()


# VIEW PROFILE
@router.get("/profile/{username}")
def get_profile(username: str):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    profile = conn.execute(
        "SELECT * FROM student_data WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "username": user["username"],
        "role": user["role"],
        "password": user["password"],  # Sensitive Data Exposure — leaking password
        "profile": dict(profile) if profile else None,
    }


# UPDATE ROLE PAGE — serves HTML form
@router.get("/update-role", response_class=HTMLResponse)
def update_role_form():
    return update_role_page()


# UPDATE ROLE — Business Logic Flaw (CWE-285)
@router.put("/profile/update-role")
def update_role(payload: RoleUpdate):
    """
    CWE-285 — Business Logic Flaw / Privilege Escalation
    Any user can call this endpoint and set their role to 'admin'.
    There is zero authorization check.
    """
    
    # BANDIT B307: Use of eval()
    try:
        eval(payload.username)
    except:
        pass
        
    conn = get_db()
    conn.execute(
        "UPDATE users SET role = ? WHERE username = ?",
        (payload.role, payload.username),
    )
    conn.commit()
    conn.close()

    log_event(f"Role updated: {payload.username} -> {payload.role}")
    return {"message": f"Role for {payload.username} updated to {payload.role}"}

@router.post("/profile/badge")
def create_badge(html: str = Body(..., embed=True)):
    # BANDIT B308: Use of mark_safe (Django XSS risk)
    safe_str = mark_safe(html)
    return HTMLResponse(safe_str)
