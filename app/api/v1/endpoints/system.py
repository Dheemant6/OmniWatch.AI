import os
import random
import asyncio
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from typing import List, Dict, Any
from pydantic import BaseModel
from app.worker.celery_app import celery_app
from app.api.dependencies import verify_basic_auth, DASHBOARD_USER, DASHBOARD_PASS
import secrets
from sqlalchemy import text
from app.db.session import engine
import redis

router = APIRouter()

@router.get("/status")
async def get_system_status(username: str = Depends(verify_basic_auth)):
    """Get the overall status of the system (Redis, DB, Worker)."""
    # Ping Redis directly
    try:
        broker_url = celery_app.conf.broker_url or "redis://localhost:6379/0"
        r = redis.Redis.from_url(broker_url, socket_connect_timeout=1)
        r.ping()
        redis_status = "Connected"
    except Exception as e:
        redis_status = f"Disconnected ({str(e)})"

    # Ping Celery Worker safely
    try:
        inspect = celery_app.control.inspect(timeout=1.0)
        active_workers = inspect.active() if inspect else None
        worker_status = "Online" if active_workers is not None else "Offline"
    except Exception:
        worker_status = "Offline"

    # Ping Database dynamically
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "Connected"
    except Exception as e:
        db_status = f"Disconnected ({str(e)})"

    if worker_status == "Offline" and db_status == "Connected":
        try:
            async with engine.connect() as conn:
                res = await conn.execute(text("SELECT id FROM scan_jobs WHERE status = 'in_progress' LIMIT 1"))
                if res.first():
                    worker_status = "Busy (Scanning)"
        except Exception:
            pass

    is_healthy = worker_status in ["Online", "Busy (Scanning)"] and redis_status == "Connected" and db_status == "Connected"

    return {
        "status": "Healthy" if is_healthy else "Degraded",
        "worker_status": worker_status,
        "database": db_status,
        "redis": redis_status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user": username
    }

@router.get("/tasks")
async def get_active_tasks(username: str = Depends(verify_basic_auth)):
    """Get the current list of active pipelines from the database."""
    try:
        task_list = []
        async with engine.connect() as conn:
            res = await conn.execute(text("SELECT id, repo_name, created_at, current_stage, task_id, status FROM scan_jobs WHERE status IN ('pending', 'in_progress') ORDER BY id DESC"))
            for row in res:
                task_list.append({
                    "id": row[4] or f"scan_job_{row[0]}",
                    "db_id": row[0],
                    "name": f"Scan: {row[1]}",
                    "worker": "Celery Worker",
                    "status": "Active",
                    "stage": row[3] or "Initializing Pipeline",
                    "time_start": str(row[2])
                })
        return {"tasks": task_list}
    except Exception as e:
        return {"tasks": [], "error": str(e)}

@router.delete("/tasks/{task_id}")
async def abort_task(task_id: str, username: str = Depends(verify_basic_auth)):
    """Abort a running celery task."""
    try:
        celery_app.control.revoke(task_id, terminate=True)
        return {"status": "success", "message": f"Task {task_id} aborted."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/insights")
async def get_insights(username: str = Depends(verify_basic_auth)):
    """Get security vulnerability insights from the database."""
    try:
        async with engine.connect() as conn:
            query_sev = text("SELECT severity, COUNT(id) FROM vulnerabilities GROUP BY severity")
            result_sev = await conn.execute(query_sev)
            severity_counts = {row[0].lower(): row[1] for row in result_sev}
            
            total_vulns = sum(severity_counts.values())
            
            query_remed = text("SELECT COUNT(id) FROM vulnerabilities WHERE remediation_patch IS NOT NULL")
            result_remed = await conn.execute(query_remed)
            remediated_count = result_remed.scalar() or 0
            
            remediation_rate = int((remediated_count / total_vulns * 100)) if total_vulns > 0 else 0
            
            query_recent = text("""
                SELECT severity, title, file_path, remediation_patch, cve_reference, description, cwe_reference
                FROM vulnerabilities 
                ORDER BY id DESC LIMIT 5
            """)
            result_recent = await conn.execute(query_recent)
            recent_findings = []
            for row in result_recent:
                sev = str(row[0]).capitalize()
                if sev == 'Medium': sev = 'Med'
                recent_findings.append({
                    "sev": sev,
                    "vuln": row[1],
                    "comp": row[2] or "Unknown",
                    "stat": "Remediated (AI)" if row[3] else "Pending PR",
                    "patch": row[3],
                    "cve": row[4] or "",
                    "description": row[5] or "",
                    "cwe": row[6] or ""
                })

            # Full findings list (no limit) for export
            query_all = text("""
                SELECT severity, title, file_path, remediation_patch, cve_reference, description, cwe_reference
                FROM vulnerabilities 
                ORDER BY id DESC
            """)
            result_all = await conn.execute(query_all)
            all_findings = []
            for row in result_all:
                sev = str(row[0]).capitalize()
                if sev == 'Medium': sev = 'Med'
                all_findings.append({
                    "sev": sev,
                    "vuln": row[1],
                    "comp": row[2] or "Unknown",
                    "stat": "Remediated (AI)" if row[3] else "Pending PR",
                    "patch": row[3],
                    "cve": row[4] or "",
                    "description": row[5] or "",
                    "cwe": row[6] or ""
                })

            query_scans = text("SELECT COUNT(id) FROM scan_jobs")
            result_scans = await conn.execute(query_scans)
            scans_count = result_scans.scalar() or 0
            
            total_scans_run = scans_count
            
            # Pick the latest scan that actually has SBOM components (not just an empty shell)
            query_sbom = text("SELECT sbom_data FROM scan_jobs WHERE sbom_data IS NOT NULL ORDER BY id DESC LIMIT 10")
            result_sbom = await conn.execute(query_sbom)
            sbom_entries = []
            import json as _json
            for sbom_row in result_sbom:
                if not sbom_row or not sbom_row[0]:
                    continue
                try:
                    sbom_json = _json.loads(sbom_row[0]) if isinstance(sbom_row[0], str) else sbom_row[0]
                    components = sbom_json.get("components", []) if isinstance(sbom_json, dict) else []
                    if components:  # Only use a scan that has actual components
                        for comp in components[:15]:
                            sbom_entries.append({
                                "name": comp.get("name", "Unknown"),
                                "version": comp.get("version", "Unknown"),
                                "type": comp.get("type", "library")
                            })
                        break  # Found a good one, stop searching
                except Exception:
                    pass
            query_scans_list = text("SELECT id, repo_url, status, created_at, completed_at FROM scan_jobs ORDER BY id DESC LIMIT 5")
            result_scans_list = await conn.execute(query_scans_list)
            recent_scans = []
            for row in result_scans_list:
                recent_scans.append({
                    "id": row[0],
                    "repo_url": row[1],
                    "status": row[2],
                    "created_at": str(row[3]) if row[3] else None,
                    "completed_at": str(row[4]) if row[4] else None
                })

            return {
                "metrics": {
                    "total_scans_run": total_scans_run,
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                    "remediation_rate": f"{remediation_rate}%"
                },
                "recent_findings": recent_findings,
                "all_findings": all_findings,
                "sbom": sbom_entries,
                "recent_scans": recent_scans
            }
    except Exception as e:
        return {"error": str(e), "metrics": None, "recent_findings": [], "recent_scans": []}

class ScanRequest(BaseModel):
    repo_url: str

@router.post("/scan")
async def trigger_scan(payload: ScanRequest, username: str = Depends(verify_basic_auth)):
    """Trigger a manual security scan from the dashboard."""
    from app.worker.tasks import run_security_scan
    
    # Extract repo name roughly from the URL for the task
    repo_name = payload.repo_url.split("github.com/")[-1].replace(".git", "")
    
    run_security_scan.delay(repo_url=payload.repo_url, repo_name=repo_name, pr_number=None)
    
    return {"status": "success", "message": f"Scan task queued for {repo_name}"}

@router.delete("/clear")
async def clear_scan_results(username: str = Depends(verify_basic_auth)):
    """Delete all scan jobs and vulnerabilities from the database."""
    try:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM vulnerabilities"))
            await conn.execute(text("DELETE FROM scan_jobs"))
        return {"status": "success", "message": "All scan results cleared."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket, token: str = Query(None)):
    """WebSocket endpoint for real-time logs simulating system events."""
    # Authenticate via query token since standard browsers can't set WS headers easily
    # A simple approach for this implementation plan is basic string match
    # Expecting token to be Base64 of admin:adminpass
    import base64
    valid_token = base64.b64encode(b"admin:adminpass").decode("utf-8")
    
    if token != valid_token:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    
    log_file_path = os.path.join(os.getcwd(), "app.log")
    
    # Create the file if it doesn't exist to prevent errors
    if not os.path.exists(log_file_path):
        with open(log_file_path, "w") as f:
            f.write(f"{datetime.utcnow().isoformat()}Z [INFO] Log file created. Waiting for genuine application events...\\n")

    try:
        with open(log_file_path, "r") as f:
            # Read all available lines initially to give history
            lines = f.readlines()
            for line in lines[-200:]:  # Send up to the last 200 lines
                await websocket.send_text(line.strip())
                await asyncio.sleep(0.01)
                
            # Now tail the file for new lines
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.5)
                    continue
                await websocket.send_text(line.strip())
            
    except WebSocketDisconnect:
        print("WebSocket client disconnected")
