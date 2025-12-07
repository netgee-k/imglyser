# app.py - FINAL FIXED VERSION
import io
import os
import json
import hashlib
import secrets
import tempfile
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
from contextlib import contextmanager

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
import exifread
import numpy as np
import traceback

# ==================== Configuration ====================
class Config:
    SECRET_KEY = os.getenv("IMGLYSER_SECRET", "dev-secret-key-change-me")
    UPLOAD_DIR = "uploads"
    RESULTS_DIR = "results"
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    SUPPORTED_FORMATS = {".jpg", ".jpeg", ".png", ".tiff", ".bmp", ".webp"}
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"

# Create directories
for dir_name in [Config.UPLOAD_DIR, Config.RESULTS_DIR, "static"]:
    os.makedirs(dir_name, exist_ok=True)

# ==================== Simple Password Hashing ====================
def hash_password(password: str) -> str:
    """Simple password hashing"""
    salt = Config.SECRET_KEY.encode()
    return hashlib.sha256(salt + password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

# ==================== Database Setup ====================
class Database:
    def __init__(self, db_path="imglyser.db"):
        self.db_path = db_path
        self.init_db()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def init_db(self):
        with self.get_connection() as conn:
            # Drop and recreate tables to ensure correct schema
            conn.execute("DROP TABLE IF EXISTS users")
            conn.execute("DROP TABLE IF EXISTS analysis_sessions")
            
            # Users table
            conn.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    full_name TEXT,
                    password_hash TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            
            # Analysis sessions table
            conn.execute("""
                CREATE TABLE analysis_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id INTEGER,
                    filename TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER,
                    status TEXT DEFAULT 'pending',
                    findings TEXT,
                    exif_data TEXT,
                    ela_path TEXT,
                    risk_score INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            # Create admin user
            password_hash = hash_password(Config.ADMIN_PASSWORD)
            try:
                conn.execute("""
                    INSERT INTO users (username, email, full_name, password_hash, is_admin)
                    VALUES (?, ?, ?, ?, 1)
                """, (Config.ADMIN_USERNAME, "admin@imglyser.local", "Administrator", password_hash))
                print(f"✓ Admin user created: {Config.ADMIN_USERNAME} / {Config.ADMIN_PASSWORD}")
            except sqlite3.IntegrityError:
                print("✓ Admin user already exists")

db = Database()

# ==================== Session Management ====================
sessions = {}

def create_session(username: str, is_admin: bool = False) -> str:
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "username": username,
        "is_admin": is_admin,
        "created": datetime.now()
    }
    return session_id

def get_session(session_id: str) -> Optional[dict]:
    if session_id in sessions:
        session = sessions[session_id]
        # Check if session is expired (24 hours)
        if datetime.now() - session["created"] < timedelta(hours=24):
            return session
        else:
            del sessions[session_id]
    return None

# ==================== Helper Functions ====================
def get_current_user(request: Request) -> Optional[dict]:
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    
    session = get_session(session_id)
    if not session:
        return None
    
    with db.get_connection() as conn:
        user = conn.execute(
            "SELECT id, username, email, full_name, is_admin FROM users WHERE username = ?",
            (session["username"],)
        ).fetchone()
    
    return dict(user) if user else None

def require_login(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user

# ==================== Image Analysis ====================
class ImageAnalyzer:
    @staticmethod
    def calculate_file_hash(file_bytes: bytes) -> str:
        return hashlib.sha256(file_bytes).hexdigest()
    
    @staticmethod
    def extract_exif(file_bytes: bytes) -> Dict:
        try:
            tags = exifread.process_file(io.BytesIO(file_bytes), details=False)
            return {str(tag): str(value) for tag, value in tags.items()}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def perform_ela(image: Image.Image) -> Optional[Image.Image]:
        try:
            if image.mode != "RGB":
                image = image.convert("RGB")
            
            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
                temp_path = tmp.name
            
            image.save(temp_path, 'JPEG', quality=90)
            compressed = Image.open(temp_path)
            
            orig_array = np.array(image, dtype=np.int16)
            comp_array = np.array(compressed, dtype=np.int16)
            
            diff_array = np.abs(orig_array - comp_array) * 10
            diff_array = np.clip(diff_array, 0, 255).astype(np.uint8)
            
            ela_img = Image.fromarray(diff_array)
            
            os.unlink(temp_path)
            return ela_img
            
        except Exception as e:
            print(f"ELA error: {e}")
            return None
    
    @staticmethod
    def analyze_image(file_bytes: bytes, filename: str) -> Dict[str, Any]:
        findings = {
            "basic_info": {},
            "exif_data": {},
            "risk_score": 0,
            "warnings": [],
            "summary": ""
        }
        
        try:
            image = Image.open(io.BytesIO(file_bytes))
            
            findings["basic_info"] = {
                "filename": filename,
                "format": image.format,
                "size": image.size,
                "width": image.width,
                "height": image.height
            }
            
            findings["exif_data"] = ImageAnalyzer.extract_exif(file_bytes)
            
            risk_score = 0
            summary_parts = []
            
            # Check for editing software
            if 'Software' in findings["exif_data"]:
                risk_score += 20
                findings["warnings"].append(f"Editing software: {findings['exif_data']['Software']}")
                summary_parts.append("Editing software detected")
            
            # Check for GPS data
            if any('GPS' in key for key in findings["exif_data"].keys()):
                risk_score += 10
                findings["warnings"].append("GPS location data found")
                summary_parts.append("GPS data present")
            
            findings["risk_score"] = min(100, risk_score)
            
            if summary_parts:
                findings["summary"] = "; ".join(summary_parts)
            else:
                findings["summary"] = "No significant issues detected"
            
            exif_count = len(findings["exif_data"])
            findings["summary"] += f" ({exif_count} EXIF tags found)"
            
        except Exception as e:
            findings["error"] = str(e)
        
        return findings

# ==================== FastAPI App ====================
app = FastAPI(
    title="imglyser Pro",
    description="Professional Image Forensics Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/results", StaticFiles(directory=Config.RESULTS_DIR), name="results")

# ==================== HTML Pages ====================
@app.get("/", response_class=HTMLResponse)
async def home():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>imglyser Pro</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background: #f8f9fa; }
            .hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 5rem 0; }
            .card { border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-dark bg-dark">
            <div class="container">
                <a class="navbar-brand" href="/">imglyser Pro</a>
                <div class="navbar-nav">
                    <a class="nav-link" href="/login">Login</a>
                    <a class="nav-link" href="/register">Register</a>
                </div>
            </div>
        </nav>
        
        <div class="hero text-center">
            <div class="container">
                <h1 class="display-4 mb-4">Image Forensics Platform</h1>
                <p class="lead mb-4">Analyze images for EXIF data, manipulation, and hidden content</p>
                <a href="/login" class="btn btn-light btn-lg px-5">Get Started</a>
            </div>
        </div>
        
        <div class="container py-5">
            <div class="row text-center">
                <div class="col-md-4 mb-4">
                    <div class="card h-100 p-4">
                        <div style="font-size: 3rem;">🔍</div>
                        <h4>EXIF Analysis</h4>
                        <p>Extract camera settings, GPS data, and editing history</p>
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="card h-100 p-4">
                        <div style="font-size: 3rem;">📊</div>
                        <h4>Manipulation Detection</h4>
                        <p>Detect image editing with Error Level Analysis</p>
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="card h-100 p-4">
                        <div style="font-size: 3rem;">🛡️</div>
                        <h4>Risk Assessment</h4>
                        <p>Evaluate image authenticity with risk scoring</p>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - imglyser Pro</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="row justify-content-center">
                <div class="col-md-4">
                    <div class="card shadow">
                        <div class="card-header bg-primary text-white">
                            <h4 class="mb-0">Login</h4>
                        </div>
                        <div class="card-body">
                            <form id="loginForm">
                                <div class="mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" class="form-control" id="username" value="admin" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" id="password" value="admin123" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Login</button>
                            </form>
                            <div class="mt-3 text-center">
                                <small class="text-muted">Demo: admin / admin123</small>
                            </div>
                            <div id="loginResult" class="mt-3"></div>
                            <div class="mt-3 text-center">
                                <a href="/register">Need an account? Register</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const resultDiv = document.getElementById('loginResult');
            
            resultDiv.innerHTML = '<div class="alert alert-info">Logging in...</div>';
            
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    resultDiv.innerHTML = '<div class="alert alert-success">Login successful! Redirecting...</div>';
                    setTimeout(() => window.location.href = '/dashboard', 1000);
                } else {
                    const error = await response.text();
                    resultDiv.innerHTML = '<div class="alert alert-danger">' + error + '</div>';
                }
            } catch (error) {
                resultDiv.innerHTML = '<div class="alert alert-danger">Network error: ' + error + '</div>';
            }
        });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - imglyser Pro</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="row justify-content-center">
                <div class="col-md-4">
                    <div class="card shadow">
                        <div class="card-header bg-primary text-white">
                            <h4 class="mb-0">Register</h4>
                        </div>
                        <div class="card-body">
                            <form id="registerForm">
                                <div class="mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" class="form-control" id="username" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Email</label>
                                    <input type="email" class="form-control" id="email" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" class="form-control" id="password" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Confirm Password</label>
                                    <input type="password" class="form-control" id="confirm_password" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Register</button>
                            </form>
                            <div id="registerResult" class="mt-3"></div>
                            <div class="mt-3 text-center">
                                <a href="/login">Already have an account? Login</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirm_password = document.getElementById('confirm_password').value;
            const resultDiv = document.getElementById('registerResult');
            
            if (password !== confirm_password) {
                resultDiv.innerHTML = '<div class="alert alert-danger">Passwords do not match!</div>';
                return;
            }
            
            resultDiv.innerHTML = '<div class="alert alert-info">Creating account...</div>';
            
            const formData = new FormData();
            formData.append('username', username);
            formData.append('email', email);
            formData.append('password', password);
            
            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    resultDiv.innerHTML = '<div class="alert alert-success">Registration successful! Redirecting to login...</div>';
                    setTimeout(() => window.location.href = '/login', 2000);
                } else {
                    const error = await response.text();
                    resultDiv.innerHTML = '<div class="alert alert-danger">' + error + '</div>';
                }
            } catch (error) {
                resultDiv.innerHTML = '<div class="alert alert-danger">Network error: ' + error + '</div>';
            }
        });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = require_login(request)
    
    with db.get_connection() as conn:
        analyses = conn.execute("""
            SELECT * FROM analysis_sessions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        """, (user["id"],)).fetchall()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - imglyser Pro</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-dark bg-dark">
            <div class="container">
                <a class="navbar-brand" href="/">imglyser Pro</a>
                <div class="navbar-nav">
                    <span class="nav-link">Welcome, {user['username']}!</span>
                    <a class="nav-link" href="/logout">Logout</a>
                </div>
            </div>
        </nav>
        
        <div class="container py-4">
            <h2 class="mb-4">Dashboard</h2>
            
            <div class="card mb-4">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0">Analyze Image</h5>
                </div>
                <div class="card-body">
                    <form id="uploadForm" enctype="multipart/form-data">
                        <div class="mb-3">
                            <input type="file" class="form-control" name="file" accept=".jpg,.jpeg,.png" required>
                            <small class="text-muted">Max 50MB. Supported: JPG, PNG</small>
                        </div>
                        <button type="submit" class="btn btn-primary">Analyze</button>
                    </form>
                    <div id="uploadResult" class="mt-3"></div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Recent Analyses</h5>
                </div>
                <div class="card-body">
                    {"".join([f'''
                    <div class="border-bottom py-2">
                        <div class="d-flex justify-content-between">
                            <div>
                                <strong>{analysis['filename']}</strong><br>
                                <small class="text-muted">{analysis['created_at']}</small>
                            </div>
                            <div>
                                <span class="badge bg-{'success' if analysis['status'] == 'completed' else 'warning'}">{analysis['status']}</span>
                                <span class="badge bg-{'danger' if analysis['risk_score'] > 70 else 'warning' if analysis['risk_score'] > 30 else 'success'} ms-2">
                                    Risk: {analysis['risk_score']}
                                </span>
                                <a href="/analysis/{analysis['session_id']}" class="btn btn-sm btn-outline-primary ms-2">View</a>
                            </div>
                        </div>
                    </div>
                    ''' for analysis in analyses]) if analyses else '<p class="text-center text-muted">No analyses yet</p>'}
                </div>
            </div>
        </div>
        
        <script>
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {{
            e.preventDefault();
            const formData = new FormData(this);
            const resultDiv = document.getElementById('uploadResult');
            
            resultDiv.innerHTML = '<div class="alert alert-info">Uploading...</div>';
            
            try {{
                const response = await fetch('/api/analyze', {{
                    method: 'POST',
                    body: formData
                }});
                
                if (response.ok) {{
                    const data = await response.json();
                    resultDiv.innerHTML = `
                        <div class="alert alert-success">
                            Analysis started!<br>
                            <a href="/analysis/${{data.session_id}}" class="btn btn-sm btn-success mt-2">View Results</a>
                        </div>
                    `;
                    setTimeout(() => location.reload(), 2000);
                }} else {{
                    const error = await response.text();
                    resultDiv.innerHTML = '<div class="alert alert-danger">' + error + '</div>';
                }}
            }} catch (error) {{
                resultDiv.innerHTML = '<div class="alert alert-danger">Network error: ' + error + '</div>';
            }}
        }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/analysis/{session_id}", response_class=HTMLResponse)
async def view_analysis(request: Request, session_id: str):
    user = require_login(request)
    
    with db.get_connection() as conn:
        analysis = conn.execute("""
            SELECT * FROM analysis_sessions 
            WHERE session_id = ? AND user_id = ?
        """, (session_id, user["id"])).fetchone()
    
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    findings = json.loads(analysis["findings"]) if analysis["findings"] else {}
    exif_data = json.loads(analysis["exif_data"]) if analysis["exif_data"] else {}
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analysis - imglyser Pro</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-dark bg-dark">
            <div class="container">
                <a class="navbar-brand" href="/dashboard">← Back to Dashboard</a>
            </div>
        </nav>
        
        <div class="container py-4">
            <h2 class="mb-4">Analysis Results</h2>
            
            <div class="card mb-4">
                <div class="card-body">
                    <h4>{analysis['filename']}</h4>
                    <p><strong>Risk Score:</strong> <span class="badge bg-{'danger' if analysis['risk_score'] > 70 else 'warning' if analysis['risk_score'] > 30 else 'success'}">{analysis['risk_score']}/100</span></p>
                    <p><strong>Summary:</strong> {findings.get('summary', 'No summary available')}</p>
                    <p><strong>Analyzed:</strong> {analysis['created_at']}</p>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5 class="mb-0">Image Information</h5>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
                                <tr><td>Width:</td><td>{findings.get('basic_info', {}).get('width', 'N/A')}</td></tr>
                                <tr><td>Height:</td><td>{findings.get('basic_info', {}).get('height', 'N/A')}</td></tr>
                                <tr><td>Format:</td><td>{findings.get('basic_info', {}).get('format', 'N/A')}</td></tr>
                                <tr><td>File Size:</td><td>{analysis['file_size'] // 1024} KB</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5 class="mb-0">EXIF Data ({len(exif_data)} tags)</h5>
                        </div>
                        <div class="card-body" style="max-height: 300px; overflow-y: auto;">
                            <table class="table table-sm">
                                {"".join([f'<tr><td><small>{key}</small></td><td><small>{str(value)[:50]}{"..." if len(str(value)) > 50 else ""}</small></td></tr>' for key, value in list(exif_data.items())[:20]])}
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            {f'''
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Warnings</h5>
                </div>
                <div class="card-body">
                    <ul>
                        {"".join([f'<li>{warning}</li>' for warning in findings.get('warnings', [])])}
                    </ul>
                </div>
            </div>
            ''' if findings.get('warnings') else ''}
            
            {f'''
            <div class="card mt-4">
                <div class="card-header">
                    <h5 class="mb-0">ELA Analysis</h5>
                </div>
                <div class="card-body text-center">
                    <img src="/{analysis['ela_path']}" class="img-fluid" style="max-height: 400px;">
                    <p class="text-muted mt-2">Error Level Analysis shows compression differences</p>
                </div>
            </div>
            ''' if analysis['ela_path'] and os.path.exists(analysis['ela_path']) else ''}
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

# ==================== API Endpoints ====================
@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """Login endpoint"""
    with db.get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", 
            (username,)
        ).fetchone()
    
    if not user:
        raise HTTPException(401, "Invalid username or password")
    
    # Debug: print user data
    print(f"User found: {dict(user)}")
    
    # Check if password_hash column exists
    user_dict = dict(user)
    if "password_hash" not in user_dict:
        print("Error: password_hash column not found in user data")
        print(f"Available columns: {list(user_dict.keys())}")
        raise HTTPException(500, "Database configuration error")
    
    if not verify_password(password, user_dict["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    
    if not user_dict.get("is_active", True):
        raise HTTPException(400, "Account disabled")
    
    # Update last login
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_dict["id"],)
        )
    
    # Create session
    session_id = create_session(username, user_dict.get("is_admin", False))
    
    response = JSONResponse({
        "success": True,
        "message": "Login successful"
    })
    
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        max_age=24*60*60
    )
    
    return response

@app.post("/api/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    """Register new user"""
    with db.get_connection() as conn:
        # Check if user exists
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()
        
        if existing:
            raise HTTPException(400, "Username or email already exists")
        
        # Create user
        password_hash = hash_password(password)
        conn.execute("""
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        """, (username, email, password_hash))
    
    return JSONResponse({"success": True, "message": "Registration successful"})

@app.post("/api/analyze")
async def analyze_image(file: UploadFile = File(...), request: Request = None):
    """Analyze image with debug logging"""
    print(f"\n=== DEBUG: Starting analysis ===")
    print(f"DEBUG: File: {file.filename}")
    
    user = get_current_user(request)
    if not user:
        print("DEBUG: User not logged in")
        raise HTTPException(401, "Not logged in")
    
    print(f"DEBUG: User: {user['username']}")
    
    try:
        # Validate file
        file_ext = Path(file.filename).suffix.lower()
        print(f"DEBUG: File extension: {file_ext}")
        
        if file_ext not in Config.SUPPORTED_FORMATS:
            raise HTTPException(400, f"Unsupported file format. Supported: {Config.SUPPORTED_FORMATS}")
        
        file_bytes = await file.read()
        print(f"DEBUG: File size: {len(file_bytes)} bytes")
        
        if len(file_bytes) > Config.MAX_FILE_SIZE:
            raise HTTPException(413, f"File too large. Max: {Config.MAX_FILE_SIZE//1024//1024}MB")
        
        # Calculate hash
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        print(f"DEBUG: File hash: {file_hash[:16]}...")
        
        # Check cache
        with db.get_connection() as conn:
            existing = conn.execute(
                "SELECT session_id FROM analysis_sessions WHERE file_hash = ?",
                (file_hash,)
            ).fetchone()
            
            if existing:
                print(f"DEBUG: Analysis found in cache")
                return JSONResponse({
                    "session_id": existing["session_id"],
                    "message": "Analysis found in cache"
                })
        
        # Create analysis session
        session_id = secrets.token_urlsafe(16)
        print(f"DEBUG: Session ID: {session_id}")
        
        with db.get_connection() as conn:
            conn.execute("""
                INSERT INTO analysis_sessions 
                (session_id, user_id, filename, file_hash, file_size, status)
                VALUES (?, ?, ?, ?, ?, 'processing')
            """, (session_id, user["id"], file.filename, file_hash, len(file_bytes)))
        
        try:
            print("DEBUG: Starting image analysis...")
            
            # Perform analysis
            analyzer = ImageAnalyzer()
            findings = analyzer.analyze_image(file_bytes, file.filename)
            print(f"DEBUG: Basic analysis complete")
            print(f"DEBUG: Findings keys: {list(findings.keys())}")
            
            # Try to save ELA image
            ela_path = None
            try:
                print("DEBUG: Attempting ELA analysis...")
                img = Image.open(io.BytesIO(file_bytes))
                print(f"DEBUG: Image opened: {img.format}, {img.size}")
                
                ela_image = analyzer.perform_ela(img)
                if ela_image:
                    ela_filename = f"ela_{session_id}.png"
                    ela_path = os.path.join(Config.RESULTS_DIR, ela_filename)
                    
                    # Make sure directory exists
                    os.makedirs(os.path.dirname(ela_path), exist_ok=True)
                    
                    ela_image.save(ela_path)
                    print(f"DEBUG: ELA saved: {ela_path}")
                else:
                    print("DEBUG: ELA generation returned None")
                    
            except Exception as ela_error:
                print(f"DEBUG: ELA failed: {ela_error}")
                import traceback
                traceback.print_exc()
                ela_path = None
            
            # Update database
            print("DEBUG: Updating database...")
            with db.get_connection() as conn:
                conn.execute("""
                    UPDATE analysis_sessions 
                    SET status = 'completed',
                        findings = ?,
                        exif_data = ?,
                        ela_path = ?,
                        risk_score = ?,
                        completed_at = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                """, (
                    json.dumps(findings),
                    json.dumps(findings.get("exif_data", {})),
                    ela_path,
                    findings.get("risk_score", 0),
                    session_id
                ))
            
            print(f"DEBUG: Analysis completed successfully")
            
            return JSONResponse({
                "session_id": session_id,
                "status": "completed",
                "risk_score": findings.get("risk_score", 0),
                "summary": findings.get("summary", "")
            })
            
        except Exception as e:
            print(f"DEBUG: Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            
            with db.get_connection() as conn:
                conn.execute("""
                    UPDATE analysis_sessions 
                    SET status = 'failed',
                        findings = ?
                    WHERE session_id = ?
                """, (json.dumps({"error": str(e)}), session_id))
            
            raise HTTPException(500, f"Analysis failed: {str(e)}")
            
    except HTTPException as http_error:
        print(f"DEBUG: HTTPException: {http_error}")
        raise
    except Exception as e:
        print(f"DEBUG: Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.get("/api/analysis/{session_id}")
async def get_analysis(session_id: str, request: Request = None):
    """Get analysis results"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Not logged in")
    
    with db.get_connection() as conn:
        analysis = conn.execute("""
            SELECT * FROM analysis_sessions 
            WHERE session_id = ? AND user_id = ?
        """, (session_id, user["id"])).fetchone()
    
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    result = dict(analysis)
    
    # Parse JSON fields
    for field in ["findings", "exif_data"]:
        if result.get(field):
            try:
                result[field] = json.loads(result[field])
            except:
                pass
    
    return JSONResponse(result)

# ==================== Health Check ====================
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    }

# ==================== Logout ====================
@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie("session_id")
    return response

# ==================== Startup ====================
@app.on_event("startup")
async def startup():
    print("\n" + "="*50)
    print("imglyser Pro - Image Forensics")
    print("="*50)
    print(f"URL: http://localhost:8000")
    print(f"Admin: {Config.ADMIN_USERNAME} / {Config.ADMIN_PASSWORD}")
    print(f"Upload directory: {Config.UPLOAD_DIR}")
    print(f"Results directory: {Config.RESULTS_DIR}")
    print("="*50)

# ==================== Run Application ====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)