"""
Vulnerable Student Management System - FOR EDUCATIONAL PURPOSES ONLY
This application intentionally contains security vulnerabilities for cybersecurity training.
DO NOT deploy this in any production environment.
"""

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.database import init_db
from app.routes import auth, profile, files
from app.templates import home_page

# ── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="Student Management System")

# ── Initialize Database ─────────────────────────────────────────────────────

init_db()

# ── Home Page ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    return home_page()

# ── Register Routers ────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(profile.router)
app.include_router(files.router)

# ── Run ──────────────────────────────────────────────────────────────────────

def run_flask_legacy():
    # BANDIT B201: Flask debug mode enabled
    from flask import Flask
    flask_app = Flask(__name__)
    flask_app.run(debug=True)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)