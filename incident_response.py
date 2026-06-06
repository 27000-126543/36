import json
import random
from datetime import datetime, timedelta
from database import get_db, log_operation
from config import SECURITY_TEAM, ALERT_FALSE_POSITIVE_THRESHOLD


def generate_mock_alerts(count=15):
    alert_types = [
        ("SQL Injection Attempt", "high"),
        ("Cross-Site Scripting (XSS)", "medium"),
        ("Brute Force Login", "high"),
        ("Port Scan Detected", "low"),
        ("Malware C2 Communication", "critical"),
        ("Data Exfiltration Attempt", "critical"),
        ("Privilege Escalation", "high"),
        ("Unauthorized Access", "medium"),
        ("Web Shell Upload", "critical"),
        ("DNS Tunneling", "medium"),
    ]
    internal_ips = [f"10.0.{x}.{y}" for x in range(1, 7) for y in range(10, 25)]
    inserted = 0
    with get_db() as conn:
        for _ in range(count):
            atype, severity = random.choice(alert_types)
            alert_time = (datetime.now() - timedelta(minutes=random.randint(5, 1440))).isoformat()
            src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
            dst_ip = random.choice(internal_ips)
            dst_port = random.choice([22, 80, 443, 3306, 3389, 8080, 6379, 21])
            payload = f"attack_payload_{random.randint(1000, 9999)}"
            conn.execute(
                """INSERT INTO ids_alerts
                   (alert_source, alert_type, severity, source_ip, destination_ip,
                    destination_port, payload, alert_time)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                ("MockIDS", atype, severity, src_ip, dst_ip, dst_port, payload, alert_time)
            )
            inserted += 1
    log_operation("alert_generate_mock", f"生成了 {inserted} 条模拟IDS告警数据")
    return inserted


def generate_mock_supporting_logs():
    with get_db() as conn:
        alerts = conn.execute(
            "SELECT * FROM ids_alerts ORDER BY alert_time DESC LIMIT 30").fetchall()
        login_count = 0
        flow_count = 0
        file_count = 0
        usernames = ["admin", "root", "test", "user01", "user02", "www-data", "postgres", "mysql"]

        for alert in alerts:
            alert_time = datetime.fromisoformat(alert["alert_time"])
            start_t = (alert_time - timedelta(minutes=10)).isoformat()
            end_t = (alert_time + timedelta(minutes=10)).isoformat()
            for _ in range(random.randint(1, 5)):
                success = 1 if random.random() > 0.6 else 0
                conn.execute(
                    """INSERT INTO login_logs
                       (username, source_ip, target_ip, login_time, success, raw_log)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        random.choice(usernames),
                        alert["source_ip"],
                        alert["destination_ip"],
                        (alert_time + timedelta(seconds=random.randint(-300, 300))).isoformat(),
                        success,
                        f"SSH login from {alert['source_ip']} to {alert['destination_ip']}"
                    )
                )
                login_count += 1
            for _ in range(random.randint(3, 10)):
                conn.execute(
                    """INSERT INTO network_flows
                       (source_ip, source_port, destination_ip, destination_port,
                        protocol, bytes_sent, bytes_received, flow_time, raw_flow)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert["source_ip"],
                        random.randint(1024, 65535),
                        alert["destination_ip"],
                        alert["destination_port"] or 80,
                        random.choice(["TCP", "UDP"]),
                        random.randint(64, 65535),
                        random.randint(64, 65535),
                        (alert_time + timedelta(seconds=random.randint(-300, 300))).isoformat(),
                        f"NetFlow {alert['source_ip']} -> {alert['destination_ip']}"
                    )
                )
                flow_count += 1
            for _ in range(random.randint(0, 3)):
                conn.execute(
                    """INSERT INTO file_changes
                       (host_ip, file_path, action, change_time, file_hash, raw_record)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        alert["destination_ip"],
                        random.choice([
                            "/etc/passwd", "/var/log/auth.log", "/tmp/backdoor.sh",
                            "/var/www/html/shell.php", "/root/.bashrc", "/etc/crontab"
                        ]),
                        random.choice(["modify", "create", "delete"]),
                        (alert_time + timedelta(seconds=random.randint(-300, 300))).isoformat(),
                        f"sha256:{random.randint(10**60, 10**64)}",
                        f"File change on {alert['destination_ip']}"
                    )
                )
                file_count += 1
    log_operation("logs_generate_mock",
                   f"生成模拟辅助日志: 登录 {login_count} 条, 流量 {flow_count} 条, 文件变更 {file_count} 条")
    return {"login": login_count, "flow": flow_count, "file": file_count}


def filter_false_positives():
    filtered = 0
    with get_db() as conn:
        alerts = conn.execute(
            "SELECT * FROM ids_alerts WHERE is_false_positive = 0 AND incident_id IS NULL").fetchall()
        for alert in alerts:
            sig_key = f"{alert['alert_type']}:{alert['destination_ip']}:{alert['destination_port']}"
            history = conn.execute(
                """SELECT COUNT(*) as cnt FROM ids_alerts
                   WHERE alert_type=? AND destination_ip=? AND destination_port=?
                     AND is_false_positive=1""",
                (alert["alert_type"], alert["destination_ip"], alert["destination_port"])
            ).fetchone()["cnt"]
            if history >= ALERT_FALSE_POSITIVE_THRESHOLD:
                conn.execute(
                    """UPDATE ids_alerts
                       SET is_false_positive=1, false_positive_count=false_positive_count+1
                       WHERE id=?""",
                    (alert["id"],)
                )
                filtered += 1
    if filtered > 0:
        log_operation("alert_filter_fp",
                       f"基于历史误报模式自动过滤了 {filtered} 条误报告警",
                       result=f"filtered={filtered}")
    return filtered


def correlate_alert_context(alert_id):
    with get_db() as conn:
        alert = conn.execute("SELECT * FROM ids_alerts WHERE id=?", (alert_id,)).fetchone()
        if not alert:
            return None
        alert_time = datetime.fromisoformat(alert["alert_time"])
        start = (alert_time - timedelta(minutes=30)).isoformat()
        end = (alert_time + timedelta(minutes=30)).isoformat()
        logins = conn.execute(
            """SELECT * FROM login_logs
               WHERE (source_ip=? OR target_ip=?) AND login_time BETWEEN ? AND ?
               ORDER BY login_time""",
            (alert["source_ip"], alert["destination_ip"], start, end)
        ).fetchall()
        flows = conn.execute(
            """SELECT * FROM network_flows
               WHERE (source_ip=? OR destination_ip=?) AND flow_time BETWEEN ? AND ?
               ORDER BY flow_time""",
            (alert["source_ip"], alert["destination_ip"], start, end)
        ).fetchall()
        files = conn.execute(
            """SELECT * FROM file_changes
               WHERE host_ip=? AND change_time BETWEEN ? AND ?
               ORDER BY change_time""",
            (alert["destination_ip"], start, end)
        ).fetchall()
        return {
            "alert": dict(alert),
            "login_logs": [dict(l) for l in logins],
            "network_flows": [dict(f) for f in flows],
            "file_changes": [dict(f) for f in files],
        }


def create_incident_from_alert(alert_id):
    with get_db() as conn:
        alert = conn.execute("SELECT * FROM ids_alerts WHERE id=?", (alert_id,)).fetchone()
        if not alert or alert["incident_id"]:
            return None
        seq = conn.execute(
            "SELECT COUNT(*) as cnt FROM security_incidents WHERE created_at >= date('now')").fetchone()["cnt"]
        incident_no = f"INC-{datetime.now().strftime('%Y%m%d')}-{seq + 1:04d}"
        severity = alert["severity"]
        if severity in ("critical", "high"):
            analysts = [a for a in SECURITY_TEAM if a["level"] in ("senior", "mid")]
        else:
            analysts = SECURITY_TEAM
        analyst = random.choice(analysts)
        title = f"[{severity.upper()}] {alert['alert_type']} - {alert['destination_ip']}"
        description = (
            f"告警来源: {alert['alert_source']}\n"
            f"告警类型: {alert['alert_type']}\n"
            f"严重级别: {severity}\n"
            f"源地址: {alert['source_ip']}\n"
            f"目标: {alert['destination_ip']}:{alert['destination_port']}\n"
            f"告警时间: {alert['alert_time']}\n"
            f"原始载荷: {alert['payload']}"
        )
        cursor = conn.execute(
            """INSERT INTO security_incidents
               (incident_no, title, description, incident_type, severity,
                analyst, analyst_email, assigned_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'assigned')""",
            (
                incident_no, title, description,
                alert["alert_type"], severity,
                analyst["name"], analyst["email"],
                datetime.now().isoformat()
            )
        )
        incident_id = cursor.lastrowid
        conn.execute(
            "UPDATE ids_alerts SET incident_id=? WHERE id=?",
            (incident_id, alert_id)
        )
    log_operation("incident_create",
                   f"根据告警 #{alert_id} 创建安全事件 #{incident_no}，已分配给 {analyst['name']}",
                   target_type="incident", target_id=incident_id)
    return {"incident_id": incident_id, "incident_no": incident_no, "analyst": analyst}


def auto_process_real_alerts():
    with get_db() as conn:
        pending = conn.execute(
            """SELECT id FROM ids_alerts
               WHERE is_false_positive=0 AND incident_id IS NULL""").fetchall()
        created = 0
        for a in pending:
            result = create_incident_from_alert(a["id"])
            if result:
                created += 1
    log_operation("incident_auto_create",
                   f"自动为真实告警创建了 {created} 个安全事件",
                   result=f"created={created}")
    return created


def resolve_incident(incident_id, affected_assets=None, affected_data=None,
                     attack_chain=None, mitigation=None, operator="system"):
    with get_db() as conn:
        conn.execute(
            """UPDATE security_incidents
               SET status='resolved', affected_assets=?, affected_data=?,
                   attack_chain=?, mitigation=?, resolved_at=?
               WHERE id=?""",
            (
                affected_assets, affected_data, attack_chain, mitigation,
                datetime.now().isoformat(), incident_id
            )
        )
    log_operation("incident_resolve",
                   f"安全事件 #{incident_id} 已标记为已解决",
                   target_type="incident", target_id=incident_id, operator=operator)
