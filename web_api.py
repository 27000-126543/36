import os
import sys
import csv
import io
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from database import init_db, get_db, log_operation
from config import TEMPLATES_DIR, STATIC_DIR, WEB_SERVER
from query_export import (
    query_history, export_tickets_to_csv, export_incidents_to_csv,
    get_operation_logs
)

init_db()

app = FastAPI(title="企业级安全事件自动化响应与漏洞闭环管理系统",
              description="Security Operations Center API",
              version="2.0.0")

try:
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
except Exception:
    pass

templates = Jinja2Templates(directory=TEMPLATES_DIR)


def _row_to_dict(row):
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    with get_db() as conn:
        stats = {
            "assets": conn.execute("SELECT COUNT(*) as c FROM assets").fetchone()["c"],
            "vulns_open": conn.execute(
                "SELECT COUNT(*) as c FROM vulnerabilities WHERE status='open'").fetchone()["c"],
            "tickets_pending": conn.execute(
                "SELECT COUNT(*) as c FROM tickets WHERE status IN ('pending','in_progress')").fetchone()["c"],
            "incidents_open": conn.execute(
                "SELECT COUNT(*) as c FROM security_incidents WHERE status != 'resolved'").fetchone()["c"],
            "iocs": conn.execute("SELECT COUNT(*) as c FROM ioc_blacklist").fetchone()["c"],
        }
    return templates.TemplateResponse("index.html", {"request": request, "stats": stats})


@app.get("/api/health")
async def health():
    return {"status": "ok", "time": datetime.now().isoformat()}


@app.get("/api/assets")
async def list_assets(
    ip: Optional[str] = None,
    department: Optional[str] = None,
    owner: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    sql = "SELECT * FROM assets WHERE 1=1"
    params = []
    if ip:
        sql += " AND ip LIKE ?"
        params.append(f"%{ip}%")
    if department:
        sql += " AND department = ?"
        params.append(department)
    if owner:
        sql += " AND asset_owner LIKE ?"
        params.append(f"%{owner}%")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        log_operation("api_query", f"资产查询: ip={ip}, dept={department}",
                       target_type="asset", result=f"count={len(rows)}")
        return {"total": len(rows), "data": [_row_to_dict(r) for r in rows]}


@app.get("/api/assets/{asset_id}")
async def get_asset(asset_id: int):
    with get_db() as conn:
        asset = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not asset:
            raise HTTPException(404, "资产不存在")
        vulns = conn.execute(
            "SELECT * FROM vulnerabilities WHERE asset_id=? ORDER BY risk_score DESC LIMIT 20",
            (asset_id,)).fetchall()
        tickets = conn.execute(
            "SELECT * FROM tickets WHERE asset_id=? ORDER BY id DESC LIMIT 20",
            (asset_id,)).fetchall()
        return {
            "asset": _row_to_dict(asset),
            "vulnerabilities": [_row_to_dict(v) for v in vulns],
            "tickets": [_row_to_dict(t) for t in tickets],
        }


@app.get("/api/vulnerabilities")
async def list_vulnerabilities(
    cve_id: Optional[str] = None,
    asset_ip: Optional[str] = None,
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    min_score: Optional[float] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    sql = """SELECT v.*, a.ip, a.hostname, a.department, a.asset_owner
             FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id WHERE 1=1"""
    params = []
    if cve_id:
        sql += " AND v.cve_id LIKE ?"
        params.append(f"%{cve_id}%")
    if asset_ip:
        sql += " AND a.ip LIKE ?"
        params.append(f"%{asset_ip}%")
    if risk_level:
        sql += " AND v.risk_level = ?"
        params.append(risk_level)
    if status:
        sql += " AND v.status = ?"
        params.append(status)
    if min_score is not None:
        sql += " AND v.risk_score >= ?"
        params.append(min_score)
    sql += " ORDER BY v.risk_score DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        log_operation("api_query",
                       f"漏洞查询: cve={cve_id}, ip={asset_ip}, level={risk_level}",
                       target_type="vulnerability", result=f"count={len(rows)}")
        return {"total": len(rows), "data": [_row_to_dict(r) for r in rows]}


@app.get("/api/incidents")
async def list_incidents(
    incident_no: Optional[str] = None,
    incident_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    sql = "SELECT * FROM security_incidents WHERE 1=1"
    params = []
    if incident_no:
        sql += " AND incident_no LIKE ?"
        params.append(f"%{incident_no}%")
    if incident_type:
        sql += " AND incident_type LIKE ?"
        params.append(f"%{incident_type}%")
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if status:
        sql += " AND status = ?"
        params.append(status)
    if asset_ip:
        sql += (" AND id IN (SELECT incident_id FROM ids_alerts "
                "WHERE source_ip LIKE ? OR destination_ip LIKE ?)")
        params.extend([f"%{asset_ip}%", f"%{asset_ip}%"])
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        log_operation("api_query",
                       f"事件查询: no={incident_no}, type={incident_type}, sev={severity}",
                       target_type="incident", result=f"count={len(rows)}")
        return {"total": len(rows), "data": [_row_to_dict(r) for r in rows]}


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int):
    with get_db() as conn:
        inc = conn.execute(
            "SELECT * FROM security_incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            raise HTTPException(404, "事件不存在")
        alerts = conn.execute(
            "SELECT * FROM ids_alerts WHERE incident_id=?", (incident_id,)).fetchall()
        iocs = conn.execute(
            "SELECT * FROM ioc_blacklist WHERE incident_id=?", (incident_id,)).fetchall()
        return {
            "incident": _row_to_dict(inc),
            "alerts": [_row_to_dict(a) for a in alerts],
            "iocs": [_row_to_dict(i) for i in iocs],
        }


@app.get("/api/tickets")
async def list_tickets(
    title: Optional[str] = None,
    priority: Optional[str] = None,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    department: Optional[str] = None,
    asset_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    sql = """SELECT t.*, a.ip, a.hostname
             FROM tickets t JOIN assets a ON a.id = t.asset_id WHERE 1=1"""
    params = []
    if title:
        sql += " AND t.title LIKE ?"
        params.append(f"%{title}%")
    if priority:
        sql += " AND t.priority = ?"
        params.append(priority)
    if status:
        sql += " AND t.status = ?"
        params.append(status)
    if assignee:
        sql += " AND t.assignee LIKE ?"
        params.append(f"%{assignee}%")
    if department:
        sql += " AND t.department = ?"
        params.append(department)
    if asset_ip:
        sql += " AND a.ip LIKE ?"
        params.append(f"%{asset_ip}%")
    sql += " ORDER BY t.id DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        log_operation("api_query",
                       f"工单查询: priority={priority}, status={status}, dept={department}",
                       target_type="ticket", result=f"count={len(rows)}")
        return {"total": len(rows), "data": [_row_to_dict(r) for r in rows]}


@app.get("/api/alerts")
async def list_alerts(
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    only_false_positive: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    sql = "SELECT * FROM ids_alerts WHERE 1=1"
    params = []
    if alert_type:
        sql += " AND alert_type LIKE ?"
        params.append(f"%{alert_type}%")
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if source_ip:
        sql += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if destination_ip:
        sql += " AND destination_ip LIKE ?"
        params.append(f"%{destination_ip}%")
    if start_time:
        sql += " AND alert_time >= ?"
        params.append(start_time)
    if end_time:
        sql += " AND alert_time <= ?"
        params.append(end_time)
    if only_false_positive is True:
        sql += " AND is_false_positive=1"
    elif only_false_positive is False:
        sql += " AND is_false_positive=0"
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        return {"total": len(rows), "data": [_row_to_dict(r) for r in rows]}


@app.get("/api/iocs")
async def list_iocs(
    ioc_type: Optional[str] = None,
    ioc_value: Optional[str] = None,
    limit: int = Query(100, ge=1, le=5000)
):
    sql = "SELECT * FROM ioc_blacklist WHERE 1=1"
    params = []
    if ioc_type:
        sql += " AND ioc_type = ?"
        params.append(ioc_type)
    if ioc_value:
        sql += " AND ioc_value LIKE ?"
        params.append(f"%{ioc_value}%")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        return {"total": len(rows), "data": [_row_to_dict(r) for r in rows]}


@app.get("/api/daily_reports")
async def list_daily_reports(limit: int = Query(30, ge=1, le=365)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM daily_reports ORDER BY report_date DESC LIMIT ?",
            (limit,)).fetchall()
        return {"total": len(rows), "data": [_row_to_dict(r) for r in rows]}


@app.get("/api/logs")
async def list_operation_logs(
    operator: Optional[str] = None,
    operation_type: Optional[str] = None,
    limit: int = Query(200, ge=1, le=5000)
):
    logs = get_operation_logs(operator=operator, operation_type=operation_type, limit=limit)
    return {"total": len(logs), "data": logs}


@app.get("/api/search")
async def combined_search(
    asset_ip: Optional[str] = None,
    cve_id: Optional[str] = None,
    event_type: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    results = query_history(
        asset_ip=asset_ip, cve_id=cve_id, event_type=event_type,
        start_time=start_time and datetime.fromisoformat(start_time) if start_time else None,
        end_time=end_time and datetime.fromisoformat(end_time) if end_time else None,
        limit=limit
    )
    log_operation("api_combined_search",
                   f"组合查询: ip={asset_ip}, cve={cve_id}, type={event_type}")
    return results


@app.get("/export/tickets.csv")
async def export_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    department: Optional[str] = None,
):
    filters = {}
    if status:
        filters["status"] = status
    if priority:
        filters["priority"] = priority
    if department:
        filters["department"] = department
    path = export_tickets_to_csv(filters=filters if filters else None)
    if not path or not os.path.exists(path):
        raise HTTPException(500, "导出失败")
    log_operation("api_export", f"工单导出: {os.path.basename(path)}",
                   target_type="export", result=path)
    return FileResponse(path, media_type="text/csv", filename=os.path.basename(path))


@app.get("/export/incidents.csv")
async def export_incidents():
    path = export_incidents_to_csv()
    if not path or not os.path.exists(path):
        raise HTTPException(500, "导出失败")
    log_operation("api_export", f"事件导出: {os.path.basename(path)}",
                   target_type="export", result=path)
    return FileResponse(path, media_type="text/csv", filename=os.path.basename(path))


@app.get("/export/incidents_reports.zip")
async def export_incident_reports():
    import zipfile
    import tempfile
    from config import REPORT_DIR
    zip_path = os.path.join(tempfile.gettempdir(),
                            f"incident_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in os.listdir(REPORT_DIR):
            if f.startswith("incident_INC-") and f.endswith(".json"):
                zf.write(os.path.join(REPORT_DIR, f), f)
    log_operation("api_export", f"事件报告批量导出: {os.path.basename(zip_path)}",
                   target_type="export")
    return FileResponse(zip_path, media_type="application/zip",
                        filename=os.path.basename(zip_path))


@app.get("/api/dashboard")
async def dashboard_stats():
    with get_db() as conn:
        today = datetime.now().date()
        start = datetime.combine(today, datetime.min.time()).isoformat()
        stats = {
            "assets": conn.execute("SELECT COUNT(*) as c FROM assets").fetchone()["c"],
            "vulns_total": conn.execute("SELECT COUNT(*) as c FROM vulnerabilities").fetchone()["c"],
            "vulns_open": conn.execute(
                "SELECT COUNT(*) as c FROM vulnerabilities WHERE status='open'").fetchone()["c"],
            "vulns_critical": conn.execute(
                "SELECT COUNT(*) as c FROM vulnerabilities WHERE risk_level='critical' AND status='open'").fetchone()["c"],
            "tickets_pending": conn.execute(
                "SELECT COUNT(*) as c FROM tickets WHERE status IN ('pending','in_progress')").fetchone()["c"],
            "incidents_open": conn.execute(
                "SELECT COUNT(*) as c FROM security_incidents WHERE status != 'resolved'").fetchone()["c"],
            "iocs": conn.execute("SELECT COUNT(*) as c FROM ioc_blacklist").fetchone()["c"],
            "today_new_vulns": conn.execute(
                "SELECT COUNT(*) as c FROM vulnerabilities WHERE discovered_at >= ?", (start,)).fetchone()["c"],
            "today_new_incidents": conn.execute(
                "SELECT COUNT(*) as c FROM security_incidents WHERE created_at >= ?", (start,)).fetchone()["c"],
            "today_new_alerts": conn.execute(
                "SELECT COUNT(*) as c FROM ids_alerts WHERE alert_time >= ?", (start,)).fetchone()["c"],
        }
        dept_stats = conn.execute("""
            SELECT department,
                   COUNT(*) as total,
                   SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed
            FROM tickets GROUP BY department""").fetchall()
        stats["by_department"] = [
            {"department": r["department"], "total": r["total"],
             "completed": r["completed"],
             "rate": round(r["completed"] / r["total"], 4) if r["total"] > 0 else 0}
            for r in dept_stats
        ]
        return stats


def run_server():
    import uvicorn
    uvicorn.run(app, host=WEB_SERVER["host"], port=WEB_SERVER["port"],
                log_level="info")


if __name__ == "__main__":
    run_server()
