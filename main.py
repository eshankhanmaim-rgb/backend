"""
Primary Startup Entrypoint for Wispbyte / Pterodactyl / Python Hosting Servers.
Startup File: main.py (or run.py)
"""
import glob
import os
import sys
from pathlib import Path

# Ensure Wispbyte / Pterodactyl '--prefix .local' site-packages are on sys.path
base_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(base_dir))
for sp in glob.glob(str(base_dir / ".local" / "lib" / "python*" / "site-packages")):
    if sp not in sys.path:
        sys.path.insert(0, sp)

import uvicorn
from app.main import app  # Exposed for ASGI servers

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(
        os.getenv("SERVER_PORT")
        or os.getenv("PORT")
        or os.getenv("P_SERVER_PORT")
        or 11731
    )
    print(f"============================================================", flush=True)
    print(f"[Pruvate] Starting FastAPI + Web Server on {host}:{port}", flush=True)
    print(f"[Pruvate] Public URL: http://78.154.103.52:{port}/", flush=True)
    print(f"============================================================", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="info")
