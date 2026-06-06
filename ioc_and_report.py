import os
import json
from datetime import datetime
from database import get_db, log_operation
from config import REPORT_DIR


def add_ioc_to_blacklist(ioc_type, ioc_value, source="system", description="",
                         incident_id=None, added_by="system", conn=None):
    def _do_add(c):
        try:
            cursor = c.execute(
                """INSERT OR IGNORE INTO ioc_blacklist
                   (ioc_type, ioc_value, source, description, added_by, incident_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (ioc_type, ioc_value, source, description, added_by, incident_id)
            )
            if cursor.lastrowid:
                log_operation("ioc_add",
                               f"添加 IOC 到黑名单: {ioc_type}={ioc_value} (来源: {source})",
                               target_type="ioc", target_id=cursor.lastrowid,
                               operator=added_by, conn=c)
                return True
            return False
        except Exception:
            return False

    if conn is not None:
        return _do_add(conn)
    with get_db() as c:
        return _do_add(c)


def extract_iocs_from_incident(incident_id):
    with get_db() as conn:
        incident = conn.execute(
            "SELECT * FROM security_incidents WHERE id=?", (incident_id,)).fetchone()
        if not incident:
            return 0
        alerts = conn.execute(
            "SELECT * FROM ids_alerts WHERE incident_id=?", (incident_id,)).fetchall()
        iocs_added = 0
        for alert in alerts:
            if alert["source_ip"]:
                added = add_ioc_to_blacklist(
                    "ip", alert["source_ip"],
                    source=f"incident-{incident['incident_no']}",
                    description=f"{alert['alert_type']} 攻击源IP",
                    incident_id=incident_id, added_by=incident["analyst"] or "system",
                    conn=conn
                )
                if added:
                    iocs_added += 1
            if alert["payload"]:
                added = add_ioc_to_blacklist(
                    "payload", alert["payload"],
                    source=f"incident-{incident['incident_no']}",
                    description=f"{alert['alert_type']} 恶意载荷特征",
                    incident_id=incident_id, added_by=incident["analyst"] or "system",
                    conn=conn
                )
                if added:
                    iocs_added += 1
        logins = conn.execute(
            """SELECT DISTINCT source_ip FROM login_logs
               WHERE target_ip IN (SELECT destination_ip FROM ids_alerts WHERE incident_id=?)
                 AND success=1""", (incident_id,)).fetchall()
        for login in logins:
            added = add_ioc_to_blacklist(
                "ip", login["source_ip"],
                source=f"incident-{incident['incident_no']}",
                description="可疑成功登录源IP",
                incident_id=incident_id, added_by=incident["analyst"] or "system",
                conn=conn
            )
            if added:
                iocs_added += 1
        log_operation("ioc_extract",
                       f"从事件 #{incident_id} 中提取并添加了 {iocs_added} 个 IOC 到黑名单",
                       target_type="incident", target_id=incident_id, conn=conn)
    return iocs_added


def generate_incident_report(incident_id, conn=None):
    def _do_gen(c):
        incident = c.execute(
            "SELECT * FROM security_incidents WHERE id=?", (incident_id,)).fetchone()
        if not incident:
            return None
        alerts = c.execute(
            "SELECT * FROM ids_alerts WHERE incident_id=?", (incident_id,)).fetchall()
        logins = c.execute(
            """SELECT * FROM login_logs
                WHERE target_ip IN (SELECT destination_ip FROM ids_alerts WHERE incident_id=?)
                ORDER BY login_time""", (incident_id,)).fetchall()
        flows = c.execute(
            """SELECT * FROM network_flows
                WHERE source_ip IN (SELECT source_ip FROM ids_alerts WHERE incident_id=?)
                   OR destination_ip IN (SELECT destination_ip FROM ids_alerts WHERE incident_id=?)
                ORDER BY flow_time LIMIT 100""", (incident_id, incident_id)).fetchall()
        files = c.execute(
            """SELECT * FROM file_changes
                WHERE host_ip IN (SELECT destination_ip FROM ids_alerts WHERE incident_id=?)
                ORDER BY change_time""", (incident_id,)).fetchall()
        iocs = c.execute(
            "SELECT * FROM ioc_blacklist WHERE incident_id=?", (incident_id,)).fetchall()

        report = {
            "incident_no": incident["incident_no"],
            "title": incident["title"],
            "incident_type": incident["incident_type"],
            "severity": incident["severity"],
            "analyst": incident["analyst"],
            "status": incident["status"],
            "created_at": incident["created_at"],
            "resolved_at": incident["resolved_at"],
            "description": incident["description"],
            "affected_assets": incident["affected_assets"],
            "affected_data": incident["affected_data"],
            "attack_chain": incident["attack_chain"],
            "mitigation": incident["mitigation"],
            "alerts": [dict(a) for a in alerts],
            "login_logs": [dict(l) for l in logins],
            "network_flows": [dict(f) for f in flows[:50]],
            "file_changes": [dict(f) for f in files],
            "extracted_iocs": [dict(i) for i in iocs],
            "generated_at": datetime.now().isoformat(),
        }

        report_path = os.path.join(REPORT_DIR, f"incident_{incident['incident_no']}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        c.execute(
            "UPDATE security_incidents SET report_generated=1 WHERE id=?",
            (incident_id,)
        )
        log_operation("incident_report_generate",
                       f"生成安全事件报告: {report_path}",
                       target_type="incident", target_id=incident_id, conn=c)
        return report_path

    if conn is not None:
        return _do_gen(conn)
    with get_db() as c:
        return _do_gen(c)


def auto_generate_reports_for_resolved():
    generated = 0
    with get_db() as conn:
        incidents = conn.execute(
            """SELECT id FROM security_incidents
               WHERE status='resolved' AND report_generated=0""").fetchall()
        incident_ids = [inc["id"] for inc in incidents]

    for inc_id in incident_ids:
        extract_iocs_from_incident(inc_id)
        path = generate_incident_report(inc_id)
        if path:
            generated += 1
    log_operation("incident_report_batch",
                   f"批量生成了 {generated} 份已解决事件的报告",
                   result=f"generated={generated}")
    return generated


def get_blacklist(ioc_type=None):
    with get_db() as conn:
        if ioc_type:
            rows = conn.execute(
                "SELECT * FROM ioc_blacklist WHERE ioc_type=? ORDER BY added_at DESC",
                (ioc_type,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ioc_blacklist ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]
