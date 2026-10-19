#!/usr/bin/env python3
"""
CyberShield Web UI v6.0 — FastAPI server.
Serve HTML UI + REST API.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from core.config import APP_NAME, APP_VERSION
from core.database import init_db
from api.routes import router


# Init DB
init_db()

# App
app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Professional Cybersecurity Toolkit",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# API
app.include_router(router)

# Static files
WEB_DIR = Path(__file__).parent / "web"
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")


@app.get("/")
def serve_index():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "version": APP_VERSION}


@app.get("/api/info")
def api_info():
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "endpoints": [
            "POST /api/password",
            "POST /api/phishing",
            "POST /api/scan/port",
            "POST /api/dns",
            "POST /api/web-audit",
            "POST /api/ssl",
            "POST /api/subdomain",
            "POST /api/directory",
            "POST /api/tech",
            "POST /api/vuln",
            "POST /api/email",
            "GET  /api/history",
            "GET  /api/stats",
        ],
    }


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 8000

    print(f"\n🛡️  {APP_NAME} v{APP_VERSION}")
    print(f"🌐 Open: http://localhost:{port}")
    print(f"📱 Mobile: http://<IP-HP>:{port}\n")

    uvicorn.run(app, host=host, port=port, log_level="info")
