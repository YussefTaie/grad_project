"""
api_fastapi_example.py  —  FastAPI Reference Implementation
============================================================
This file shows how to wire the new async db.py into a FastAPI app.
It is a standalone reference — it does NOT replace the existing api.py (Flask).

To run:
    pip install fastapi uvicorn asyncpg
    uvicorn api_fastapi_example:app --reload --port 8000

Endpoints shown:
    GET  /alerts              — list alerts with pagination
    POST /alerts/{id}/read    — mark one alert as read
    GET  /health              — system health check
"""

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

import db


# ──────────────────────────────────────────────────────────────────────────────
# LIFESPAN — init and close the DB pool cleanly
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context:
      startup  → init asyncpg pool (min=5, max=20)
      shutdown → close pool gracefully
    """
    await db.init_pool()
    yield
    await db.close_pool()


app = FastAPI(
    title       = "IDS/IPS SOC API",
    description = "Real-time intrusion detection and prevention system API.",
    version     = "2.0.0",
    lifespan    = lifespan,
)


# ──────────────────────────────────────────────────────────────────────────────
# GET /alerts
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/alerts", summary="List IPS alerts (newest first)")
async def list_alerts(
    limit:       int           = Query(default=50,    ge=1, le=200,  description="Max rows"),
    offset:      int           = Query(default=0,     ge=0,          description="Pagination offset"),
    ip:          Optional[str] = Query(default=None,                 description="Filter by source IP"),
    unread_only: bool          = Query(default=False,                description="Return only unread alerts"),
):
    """
    Returns the most recent IPS alerts ordered by created_at DESC.

    Supports:
    - Pagination  : ?limit=50&offset=100
    - IP filter   : ?ip=192.168.1.5
    - Unread only : ?unread_only=true

    Response body:
    ```json
    [
      {
        "id":      1,
        "ip":      "192.168.1.5",
        "type":    "BLOCK",
        "message": "IP blocked due to DDoS: ...",
        "is_read": false,
        "time":    "2026-04-17T10:30:00.123456"
      }
    ]
    ```
    """
    rows = await db.get_alerts(
        limit       = limit,
        offset      = offset,
        ip          = ip,
        unread_only = unread_only,
    )
    total = await db.get_alerts_count(unread_only=unread_only)

    return JSONResponse(
        content = {
            "alerts":  rows,
            "total":   total,
            "limit":   limit,
            "offset":  offset,
        }
    )


# ──────────────────────────────────────────────────────────────────────────────
# POST /alerts/{id}/read
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/alerts/{alert_id}/read", summary="Mark alert as read")
async def mark_read(alert_id: int):
    """
    Marks a single alert as read by its primary key ID.

    Response 200: { "ok": true }
    Response 404: alert not found
    Response 503: database unavailable
    """
    if not await db.db_ping():
        raise HTTPException(status_code=503, detail="Database unavailable")

    ok = await db.mark_alert_read(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    return {"ok": True}


# ──────────────────────────────────────────────────────────────────────────────
# GET /health
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/health", summary="System health check")
async def health():
    """Returns DB reachability and pool status."""
    db_ok = await db.db_ping()
    pool  = db.get_pool()

    return {
        "status":    "ok" if db_ok else "degraded",
        "db_status": "ok" if db_ok else "unavailable",
        "pool": {
            "min_size": db.POOL_MIN_SIZE,
            "max_size": db.POOL_MAX_SIZE,
            "active":   pool.get_size() if pool else 0,
            "idle":     pool.get_idle_size() if pool else 0,
        } if pool else None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# BACKGROUND TASK EXAMPLE (truly non-blocking fire-and-forget)
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/example/detect", summary="Example: store detection in background")
async def example_detect(background_tasks: BackgroundTasks, src_ip: str, result: str):
    """
    Shows how to use FastAPI BackgroundTasks for truly non-blocking DB writes.
    The response is returned immediately; the DB insert happens after.

    In production, use this pattern in /predict instead of daemon threads.
    """
    background_tasks.add_task(
        db.insert_detection,
        src_ip      = src_ip,
        result      = result,
        attack_type = "EXAMPLE",
        confidence  = 0.99,
        iso_flag    = 0,
    )
    return {"queued": True, "src_ip": src_ip}
