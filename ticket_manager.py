import random
from datetime import datetime, timedelta
from database import get_db, log_operation
from config import TICKET_ESCALATION, DEPARTMENT_HEADS, SECURITY_TEAM


def _get_difficulty_from_risk(risk_level):
    mapping = {
        "critical": "hard",
        "high": "medium",
        "medium": "easy",
        "low": "easy",
    }
    return mapping.get(risk_level, "medium")


def _get_priority_from_risk(risk_level):
    mapping = {
        "critical": "urgent",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(risk_level, "medium")


def _assign_ticket_handler(asset_owner, owner_email, difficulty, risk_level):
    if risk_level in ("critical", "high") or difficulty == "hard":
        seniors = [s for s in SECURITY_TEAM if s["level"] in ("senior", "mid")]
        handler = random.choice(seniors)
    else:
        handler = random.choice(SECURITY_TEAM)
    return {
        "asset_owner": asset_owner,
        "asset_owner_email": owner_email,
        "security_handler": handler["name"],
        "security_handler_email": handler["email"],
    }


def auto_create_tickets_from_vulnerabilities():
    with get_db() as conn:
        open_vulns = conn.execute("""
            SELECT v.id as vuln_id, v.asset_id, v.title, v.description,
                   v.risk_level, v.risk_score, v.cve_id,
                   a.asset_owner, a.owner_email, a.ip, a.hostname, a.department
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.status = 'open'
              AND v.id NOT IN (SELECT vuln_id FROM tickets)""").fetchall()

        created = 0
        for vuln in open_vulns:
            difficulty = _get_difficulty_from_risk(vuln["risk_level"])
            priority = _get_priority_from_risk(vuln["risk_level"])
            assignees = _assign_ticket_handler(
                vuln["asset_owner"], vuln["owner_email"],
                difficulty, vuln["risk_level"]
            )
            title = f"[{vuln['risk_level'].upper()}] {vuln['ip']} - {vuln['title'] or vuln['cve_id']}"
            description = (
                f"资产: {vuln['ip']} ({vuln['hostname']})\n"
                f"部门: {vuln['department']}\n"
                f"漏洞编号: {vuln['cve_id'] or 'N/A'}\n"
                f"风险评分: {vuln['risk_score']}\n"
                f"修复难度: {difficulty}\n\n"
                f"漏洞描述:\n{vuln['description']}\n\n"
                f"资产负责人: {vuln['asset_owner']} ({vuln['owner_email']})"
            )
            conn.execute(
                """INSERT INTO tickets
                   (vuln_id, asset_id, title, description, priority,
                    assignee, assignee_email, department, difficulty, assigned_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    vuln["vuln_id"], vuln["asset_id"], title, description,
                    priority, assignees["asset_owner"], assignees["asset_owner_email"],
                    vuln["department"], difficulty, datetime.now().isoformat()
                )
            )
            created += 1

    log_operation("ticket_auto_create",
                   f"自动根据高风险漏洞创建了 {created} 个修复工单",
                   target_type="ticket", result=f"created={created}")
    return created


def escalate_overdue_tickets():
    start_threshold = timedelta(hours=TICKET_ESCALATION["start_hours"])
    reminder_interval = timedelta(hours=TICKET_ESCALATION["reminder_interval_hours"])
    now = datetime.now()
    escalated = 0
    reminded = 0

    with get_db() as conn:
        pending = conn.execute("""
            SELECT t.*, a.department
            FROM tickets t
            JOIN assets a ON a.id = t.asset_id
            WHERE t.status IN ('pending', 'in_progress')
              AND t.started_at IS NULL""").fetchall()

        for t in pending:
            created_at = datetime.fromisoformat(t["created_at"])
            elapsed = now - created_at
            if elapsed >= start_threshold:
                head = DEPARTMENT_HEADS.get(t["department"])
                if not head:
                    continue
                if t["escalated_at"] is None:
                    conn.execute(
                        """UPDATE tickets
                           SET escalated_at = ?,
                               last_reminder_at = ?,
                               reminder_count = reminder_count + 1
                           WHERE id = ?""",
                        (now.isoformat(), now.isoformat(), t["id"])
                    )
                    escalated += 1
                    log_operation("ticket_escalation",
                                   f"工单 #{t['id']} 已超时升级至 {head['name']} ({head['email']})",
                                   target_type="ticket", target_id=t["id"])
                else:
                    last_reminder = datetime.fromisoformat(t["last_reminder_at"]) if t["last_reminder_at"] else created_at
                    if now - last_reminder >= reminder_interval:
                        conn.execute(
                            """UPDATE tickets
                               SET last_reminder_at = ?,
                                   reminder_count = reminder_count + 1
                               WHERE id = ?""",
                            (now.isoformat(), t["id"])
                        )
                        reminded += 1
                        log_operation("ticket_reminder",
                                       f"工单 #{t['id']} 第 {t['reminder_count'] + 1} 次催办: {head['name']}",
                                       target_type="ticket", target_id=t["id"])
    total = escalated + reminded
    if total > 0:
        log_operation("ticket_escalation_check",
                       f"工单升级催办检查完成，升级 {escalated} 个，催办 {reminded} 个",
                       result=f"escalated={escalated}, reminded={reminded}")
    return {"escalated": escalated, "reminded": reminded}


def start_ticket(ticket_id, operator="system"):
    with get_db() as conn:
        conn.execute(
            "UPDATE tickets SET status='in_progress', started_at=? WHERE id=?",
            (datetime.now().isoformat(), ticket_id)
        )
    log_operation("ticket_start", f"处理人开始处理工单 #{ticket_id}",
                   target_type="ticket", target_id=ticket_id, operator=operator)


def complete_ticket(ticket_id, operator="system"):
    with get_db() as conn:
        conn.execute(
            "UPDATE tickets SET status='completed', completed_at=? WHERE id=?",
            (datetime.now().isoformat(), ticket_id)
        )
        ticket = conn.execute("SELECT vuln_id FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        if ticket:
            conn.execute(
                "UPDATE vulnerabilities SET status='fixed' WHERE id=?",
                (ticket["vuln_id"],)
            )
    log_operation("ticket_complete", f"工单 #{ticket_id} 已标记完成，对应漏洞已关闭",
                   target_type="ticket", target_id=ticket_id, operator=operator)


def get_ticket_statistics():
    with get_db() as conn:
        stats = {}
        rows = conn.execute("""
            SELECT status, COUNT(*) as cnt FROM tickets GROUP BY status""").fetchall()
        for r in rows:
            stats[r["status"]] = r["cnt"]
        rows = conn.execute("""
            SELECT priority, COUNT(*) as cnt FROM tickets
            WHERE status != 'completed' GROUP BY priority""").fetchall()
        stats["by_priority"] = {r["priority"]: r["cnt"] for r in rows}
        rows = conn.execute("""
            SELECT department, COUNT(*) as cnt FROM tickets
            WHERE status != 'completed' GROUP BY department""").fetchall()
        stats["by_department"] = {r["department"]: r["cnt"] for r in rows}
        return stats


def get_department_fix_rate(department, start_date=None, end_date=None, conn=None):
    def _calc(c):
        sql = "SELECT COUNT(*) as total FROM tickets WHERE department=?"
        params = [department]
        if start_date:
            sql += " AND created_at >= ?"
            params.append(start_date.isoformat())
        if end_date:
            sql += " AND created_at <= ?"
            params.append(end_date.isoformat())
        total = c.execute(sql, params).fetchone()["total"]
        if total == 0:
            return 0.0
        sql2 = sql.replace("COUNT(*) as total", "COUNT(*) as completed").replace(
            "WHERE department=?", "WHERE department=? AND status='completed'"
        )
        params2 = list(params)
        completed = c.execute(sql2, params2).fetchone()["completed"]
        return round(completed / total, 4)

    if conn is not None:
        return _calc(conn)
    with get_db() as c:
        return _calc(c)
