# run.py
#!/usr/bin/env python3
"""
imglyser Pro - Professional Image Forensics Platform
"""

import uvicorn
import sys
import os

if __name__ == "__main__":
    # Set environment variables
    os.environ.setdefault("IMGLYSER_ENV", "production")
    
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║                imglyser Pro v2.0                  ║
    ║       Professional Image Forensics Platform       ║
    ╚═══════════════════════════════════════════════════╝
    
    Starting server...
    """)
    
    print(f"📊 Admin Dashboard: http://localhost:8000/admin")
    print(f"🔐 Default admin: admin / Admin@123")
    print(f"📚 API Docs: http://localhost:8000/api/docs")
    print(f"📁 Database: imglyser.db")
    print(f"📂 Uploads: uploads/")
    print(f"📊 Results: results/")
    print("\nPress Ctrl+C to stop\n")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )
