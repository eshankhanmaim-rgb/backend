import os
import sys
from pathlib import Path

# Ensure backend root is on sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app.main import app as _fastapi_app


class VercelPathFixer:
    """
    ASGI middleware for Vercel Serverless Functions.
    Restores the original client URL path from Vercel's 'x-matched-path'
    header when requests are rewritten to /api/index.py.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") in ("http", "websocket"):
            headers = dict(scope.get("headers", []))
            matched_path = headers.get(b"x-matched-path")
            if matched_path:
                path_str = matched_path.decode("latin1")
                if "?" in path_str:
                    path_str = path_str.split("?", 1)[0]
                scope["path"] = path_str
                scope["raw_path"] = path_str.encode("latin1")
            elif scope.get("path") in ("/api/index.py", "/api/index"):
                scope["path"] = "/"
                scope["raw_path"] = b"/"
        await self.app(scope, receive, send)


app = VercelPathFixer(_fastapi_app)
