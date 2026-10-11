import os
import sys
from pathlib import Path
from urllib.parse import parse_qs

# Ensure backend root is on sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app.main import app as fastapi_app


async def app(scope, receive, send):
    """
    ASGI entrypoint for Vercel Serverless Functions.
    Restores the real URL path passed via rewrite query param '__vercel_path'
    or Vercel proxy headers.
    """
    if scope.get("type") in ("http", "websocket"):
        query_str = scope.get("query_string", b"").decode("latin1")
        query_params = parse_qs(query_str) if query_str else {}

        headers = dict(scope.get("headers", []))
        matched_path = headers.get(b"x-matched-path")
        forwarded_uri = headers.get(b"x-forwarded-uri")

        real_path = None
        if "__vercel_path" in query_params:
            real_path = query_params["__vercel_path"][0]
            # Strip __vercel_path from query string so FastAPI query parsing is clean
            clean_qs = "&".join(
                f"{k}={v}"
                for k, vs in query_params.items()
                if k != "__vercel_path"
                for v in vs
            )
            scope["query_string"] = clean_qs.encode("latin1")
        elif matched_path:
            real_path = matched_path.decode("latin1")
        elif forwarded_uri:
            real_path = forwarded_uri.decode("latin1")

        if real_path:
            if "?" in real_path:
                real_path = real_path.split("?", 1)[0]
            if not real_path.startswith("/"):
                real_path = "/" + real_path
            scope["path"] = real_path
            scope["raw_path"] = real_path.encode("latin1")
        elif scope.get("path") in ("/api/index.py", "/api/index"):
            scope["path"] = "/"
            scope["raw_path"] = b"/"

    await fastapi_app(scope, receive, send)
