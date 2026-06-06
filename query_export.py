import os
import json
import csv
from datetime import datetime, timedelta
from database import get_db, log_operation
from config import AUDIT_TRIGGER, DEPARTMENT_HEADS, EXPORT_DIR
from ticket_manager import get_department_fix_rate


def check_and_trigger_audit():
    triggered = []
    today = datetime.now()
    this_month = today.strftime("%Y-%m")
    last_month = (today.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    pending_logs = []

    with get_db() as conn:
        for dept in DEPARTMENT_HEADS.keys():
            fix_rates = []
            for month_str in [last_month, this_month]:
                y, m = map(int, month_str.split("-"))
                start = datetime(y, m, 1)
                if m == 12:
                    end = datetime(y + 1, 1, 1)
                else:
                    end = datetime(y, m + 1, 1)
                rate = get_department_fix_rate(dept, start, end, conn=conn)
                fix_rates.append((month_str, rate))
                conn.execute(
                    """INSERT OR REPLACE INTO department_audit
                       (department, audit_month, vuln_fix_rate) VALUES (?, ?, ?)""",
                    (dept, month_str, rate)
                )

            if all(r < AUDIT_TRIGGER["min_fix_rate"] for _, r in fix_rates):
                last_audit = conn.execute(
                    """SELECT id, triggered FROM department_audit
                       WHERE department=? AND audit_month=? AND triggered=1""",
                    (dept, this_month)).fetchone()
                if not last_audit:
                    conn.execute(
                        """UPDATE department_audit SET triggered=1, audit_status='in_progress'
                           WHERE department=? AND audit_month=?""",
                        (dept, this_month)
                    )
                    head = DEPARTMENT_HEADS[dept]
                    triggered.append({
                        "department": dept,
                        "head": head["name"],
                        "email": head["email"],
                        "fix_rates": fix_rates,
                    })
                    pending_logs.append((dept, fix_rates))

    for dept, fix_rates in pending_logs:
        log_operation("audit_trigger",
                       f"{dept} 连续两个月修复率低于阈值，已触发专项安全审计",
                       target_type="audit",
                       result=f"rates={fix_rates}, threshold={AUDIT_TRIGGER['min_fix_rate']}")
    return triggered


def _build_where(filters, table_alias, ip_fields, time_field, cve_field=None):
    clauses = []
    params = []
    if filters.get("asset_ip"):
        ip_checks = []
        for f in ip_fields:
            if "." in f:
                ip_checks.append(f"{f} = ?")
            else:
                ip_checks.append(f"{table_alias}.{f} = ?")
        clauses.append("(" + " OR ".join(ip_checks) + ")")
        params.extend([filters["asset_ip"]] * len(ip_fields))
    if filters.get("cve_id") and cve_field:
        field = cve_field if "." in cve_field else f"{table_alias}.{cve_field}"
        clauses.append(f"{field} LIKE ?")
        params.append(f"%{filters['cve_id']}%")
    if filters.get("start_time"):
        field = time_field if "." in time_field else f"{table_alias}.{time_field}"
        clauses.append(f"{field} >= ?")
        params.append(filters["start_time"].isoformat() if isinstance(filters["start_time"], datetime) else filters["start_time"])
    if filters.get("end_time"):
        field = time_field if "." in time_field else f"{table_alias}.{time_field}"
        clauses.append(f"{field} <= ?")
        params.append(filters["end_time"].isoformat() if isinstance(filters["end_time"], datetime) else filters["end_time"])
    where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where_sql, params


def query_history(asset_ip=None, cve_id=None, event_type=None,
                  start_time=None, end_time=None, limit=100):
    filters = {
        "asset_ip": asset_ip, "cve_id": cve_id,
        "start_time": start_time, "end_time": end_time,
    }
    results = {}
    with get_db() as conn:
        where_v, params_v = _build_where(filters, "v", ["a.ip"], "discovered_at", "cve_id")
        vulns = conn.execute(f"""
            SELECT v.*, a.ip, a.hostname, a.department, a.asset_owner
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            {where_v}
            ORDER BY v.discovered_at DESC LIMIT ?""", params_v + [limit]).fetchall()
        results["vulnerabilities"] = [dict(v) for v in vulns]

        if event_type in (None, "alert", "incident"):
            where_a, params_a = _build_where(filters, "t", ["source_ip", "destination_ip"], "alert_time")
            alerts = conn.execute(f"""
                SELECT t.* FROM ids_alerts t
                LEFT JOIN assets a ON a.ip = t.destination_ip
                {where_a}
                ORDER BY t.alert_time DESC LIMIT ?""", params_a + [limit]).fetchall()
            results["alerts"] = [dict(a) for a in alerts]

        if event_type in (None, "incident"):
            clauses_extra = []
            params_s = []
            if filters.get("start_time"):
                clauses_extra.append("s.created_at >= ?")
                params_s.append(filters["start_time"].isoformat() if isinstance(filters["start_time"], datetime) else filters["start_time"])
            if filters.get("end_time"):
                clauses_extra.append("s.created_at <= ?")
                params_s.append(filters["end_time"].isoformat() if isinstance(filters["end_time"], datetime) else filters["end_time"])
            if filters.get("asset_ip"):
                clauses_extra.append("""(s.id IN (SELECT incident_id FROM ids_alerts
                                     WHERE source_ip = ? OR destination_ip = ?))""")
                params_s.extend([filters["asset_ip"], filters["asset_ip"]])
            where_s = (" WHERE " + " AND ".join(clauses_extra)) if clauses_extra else ""
            incidents = conn.execute(f"""
                SELECT s.* FROM security_incidents s
                {where_s}
                ORDER BY s.created_at DESC LIMIT ?""", params_s + [limit]).fetchall()
            results["incidents"] = [dict(s) for s in incidents]

        if event_type in (None, "ticket"):
            where_tk, params_tk = _build_where(filters, "tk", ["a.ip"], "created_at")
            tickets = conn.execute(f"""
                SELECT tk.*, a.ip, a.hostname FROM tickets tk
                JOIN assets a ON a.id = tk.asset_id
                {where_tk}
                ORDER BY tk.created_at DESC LIMIT ?""", params_tk + [limit]).fetchall()
            results["tickets"] = [dict(t) for t in tickets]

    log_operation("history_query",
                   f"历史记录查询: asset_ip={asset_ip}, cve_id={cve_id}, event_type={event_type}, "
                   f"time_range={start_time}~{end_time}, 结果数={sum(len(v) for v in results.values())}")
    return results


def export_tickets_to_csv(ticket_ids=None, filters=None, filename=None):
    if not filename:
        filename = f"tickets_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(EXPORT_DIR, filename)

    with get_db() as conn:
        sql = """SELECT t.*, a.ip, a.hostname, a.department, a.asset_owner, a.os
                 FROM tickets t JOIN assets a ON a.id = t.asset_id"""
        params = []
        clauses = []
        if ticket_ids:
            clauses.append(f"t.id IN ({','.join(['?'] * len(ticket_ids))})")
            params.extend(ticket_ids)
        if filters:
            for k, v in filters.items():
                clauses.append(f"t.{k} = ?")
                params.append(v)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY t.created_at DESC"
        rows = conn.execute(sql, params).fetchall()

    if not rows:
        return None

    fieldnames = ["id", "title", "priority", "status", "difficulty", "department",
                  "asset_owner", "ip", "hostname", "os", "assignee", "assignee_email",
                  "created_at", "assigned_at", "started_at", "completed_at",
                  "escalated_at", "reminder_count", "description"]
    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(dict(r))

    log_operation("export_tickets",
                   f"批量导出工单明细 {len(rows)} 条 -> {filepath}",
                   result=f"rows={len(rows)}, path={filepath}")
    return filepath


def export_incidents_to_csv(incident_ids=None, filename=None):
    if not filename:
        filename = f"incidents_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(EXPORT_DIR, filename)

    with get_db() as conn:
        sql = "SELECT * FROM security_incidents"
        params = []
        if incident_ids:
            sql += f" WHERE id IN ({','.join(['?'] * len(incident_ids))})"
            params = incident_ids
        sql += " ORDER BY created_at DESC"
        rows = conn.execute(sql, params).fetchall()

    if not rows:
        return None

    fieldnames = ["id", "incident_no", "title", "incident_type", "severity", "status",
                  "analyst", "analyst_email", "affected_assets", "affected_data",
                  "attack_chain", "mitigation", "created_at", "assigned_at", "resolved_at"]
    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(dict(r))

    incident_reports_dir = os.path.join(EXPORT_DIR, f"incident_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(incident_reports_dir, exist_ok=True)
    from config import REPORT_DIR
    for r in rows:
        src = os.path.join(REPORT_DIR, f"incident_{r['incident_no']}.json")
        if os.path.exists(src):
            import shutil
            shutil.copy(src, os.path.join(incident_reports_dir, f"incident_{r['incident_no']}.json"))

    log_operation("export_incidents",
                   f"批量导出事件报告 {len(rows)} 条 -> {filepath}",
                   result=f"rows={len(rows)}, path={filepath}")
    return filepath


def get_operation_logs(operator=None, operation_type=None, target_type=None,
                       start_time=None, end_time=None, limit=500):
    with get_db() as conn:
        sql = "SELECT * FROM operation_logs"
        clauses = []
        params = []
        if operator:
            clauses.append("operator = ?")
            params.append(operator)
        if operation_type:
            clauses.append("operation_type = ?")
            params.append(operation_type)
        if target_type:
            clauses.append("target_type = ?")
            params.append(target_type)
        if start_time:
            clauses.append("operation_time >= ?")
            params.append(start_time.isoformat() if isinstance(start_time, datetime) else start_time)
        if end_time:
            clauses.append("operation_time <= ?")
            params.append(end_time.isoformat() if isinstance(end_time, datetime) else end_time)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY operation_time DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
