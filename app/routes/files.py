"""
File upload and download routes.
"""

import os
import shutil
import pickle
import marshal
import subprocess
import xml.etree.ElementTree as ET

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

from app.config import UPLOAD_DIR
from app.utils import log_event
from app.templates import upload_page, download_page

router = APIRouter()


# UPLOAD PAGE — serves HTML form
@router.get("/upload", response_class=HTMLResponse)
def upload_form():
    return upload_page()


# FILE UPLOAD — Insecure File Upload (CWE-434)
@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    CWE-434 — Insecure File Upload
    No validation of file extension, MIME type, or content.
    The file is saved directly to the uploads directory using shutil.
    An attacker could upload a malicious executable or web shell.
    """
    destination = os.path.join(UPLOAD_DIR, file.filename)

    with open(destination, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # BANDIT B605: Starting process with shell.
    # Exposing the filename to shell trivially enables RCE.
    os.system("ls -l" + file.filename)
    
    # BANDIT B602: Subprocess call with shell=True
    subprocess.call("ls " + file.filename, shell=True)
    
    # BANDIT B603: Subprocess without shell but unsafe input
    subprocess.call(["ls", file.filename])
    
    # BANDIT B604: Any other subprocess with shell=True
    subprocess.Popen(file.filename, shell=True)

    # BANDIT B607: Starting process with partial path
    subprocess.call("ls")

    log_event(f"File uploaded: {file.filename}")
    return {"message": f"File '{file.filename}' uploaded successfully"}

@router.post("/upload/pickle")
async def upload_pickle(file: UploadFile = File(...)):
    # BANDIT B301: Pickle usage (unsafe deserialization)
    data = await file.read()
    obj = pickle.loads(data)
    
    # BANDIT B302: Marshal usage
    marshaled = marshal.loads(data)
    return {"msg": "Deserialized successfully"}

@router.post("/upload/xml")
async def upload_xml(file: UploadFile = File(...)):
    # BANDIT B314-B320: Insecure XML parsing (XXE risks)
    data = await file.read()
    # BANDIT B108: Hardcoded temp file path
    with open("/tmp/file.xml", "wb") as f:
        f.write(data)
    
    tree = ET.parse("/tmp/file.xml")
    return {"root": tree.getroot().tag}


# DOWNLOAD PAGE — serves HTML form
@router.get("/download", response_class=HTMLResponse)
def download_form():
    return download_page()


# FILE DOWNLOAD — Path Traversal (CWE-22)
@router.get("/download/{filename:path}")
def download_file(filename: str):
    """
    CWE-22 — Path Traversal
    The filename from the URL is appended directly to the upload directory
    without sanitizing '../' sequences.  An attacker can read arbitrary
    files on the server, e.g.:
        GET /download/../../etc/passwd
    """
    filepath = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")

    log_event(f"File downloaded: {filename}")
    return FileResponse(filepath)
