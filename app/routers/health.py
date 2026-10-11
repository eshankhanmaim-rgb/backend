from fastapi import APIRouter, Request
from datetime import datetime, timezone

router = APIRouter(tags=["health"])

@router.get("/health")
async def health(request: Request):
    db_ok = True
    try:
        await request.state.db.get_settings()
    except Exception:
        db_ok = False
    return {
        "ok": True,
        "db": "ok" if db_ok else "error",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
