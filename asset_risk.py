import json
import random
from datetime import datetime
from database import get_db, log_operation
from config import RISK_WEIGHTS


def seed_sample_assets():
    sample_assets = [
        {"ip": "10.0.1.10", "hostname": "web-prod-01", "os": "CentOS 7", "department": "技术部",
         "asset_owner": "张开发", "owner_email": "zhangkaifa@company.com", "asset_value": 10,
         "applications": "Nginx,Java,Spring Boot"},
        {"ip": "10.0.1.11", "hostname": "web-prod-02", "os": "CentOS 7", "department": "技术部",
         "asset_owner": "张开发", "owner_email": "zhangkaifa@company.com", "asset_value": 10,
         "applications": "Nginx,Java,Spring Boot"},
        {"ip": "10.0.1.20", "hostname": "db-prod-01", "os": "Ubuntu 20.04", "department": "技术部",
         "asset_owner": "李DBA", "owner_email": "lidba@company.com", "asset_value": 10,
         "applications": "MySQL 8.0,Redis"},
        {"ip": "10.0.2.10", "hostname": "app-api-01", "os": "Ubuntu 22.04", "department": "技术部",
         "asset_owner": "王后端", "owner_email": "wanghoud@company.com", "asset_value": 8,
         "applications": "Python,Django,PostgreSQL"},
        {"ip": "10.0.2.20", "hostname": "cache-redis-01", "os": "Debian 11", "department": "运维部",
         "asset_owner": "赵运维", "owner_email": "zhaoyunwei@company.com", "asset_value": 7,
         "applications": "Redis 6.2"},
        {"ip": "10.0.3.10", "hostname": "mail-server", "os": "CentOS 8", "department": "运维部",
         "asset_owner": "赵运维", "owner_email": "zhaoyunwei@company.com", "asset_value": 9,
         "applications": "Postfix,Dovecot"},
        {"ip": "10.0.3.20", "hostname": "file-server", "os": "Windows Server 2019", "department": "运维部",
         "asset_owner": "孙运维", "owner_email": "sunyunwei@company.com", "asset_value": 8,
         "applications": "SMB,Active Directory"},
        {"ip": "10.0.4.10", "hostname": "market-web", "os": "Ubuntu 20.04", "department": "市场部",
         "asset_owner": "周运营", "owner_email": "zhouyunying@company.com", "asset_value": 6,
         "applications": "WordPress,PHP,Apache"},
        {"ip": "10.0.5.10", "hostname": "finance-erp", "os": "Windows Server 2016", "department": "财务部",
         "asset_owner": "吴会计", "owner_email": "wukuaiji@company.com", "asset_value": 10,
         "applications": "用友ERP,SQL Server"},
        {"ip": "10.0.5.20", "hostname": "finance-db", "os": "Windows Server 2019", "department": "财务部",
         "asset_owner": "吴会计", "owner_email": "wukuaiji@company.com", "asset_value": 10,
         "applications": "SQL Server 2019"},
        {"ip": "10.0.6.10", "hostname": "jenkins-ci", "os": "CentOS 7", "department": "技术部",
         "asset_owner": "郑开发", "owner_email": "zhengkaifa@company.com", "asset_value": 7,
         "applications": "Jenkins,Docker"},
        {"ip": "10.0.6.20", "hostname": "gitlab-server", "os": "Ubuntu 22.04", "department": "技术部",
         "asset_owner": "郑开发", "owner_email": "zhengkaifa@company.com", "asset_value": 9,
         "applications": "GitLab CE"},
    ]
    count = 0
    with get_db() as conn:
        for a in sample_assets:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO assets
                       (ip, hostname, os, department, asset_owner, owner_email, asset_value, applications)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (a["ip"], a["hostname"], a["os"], a["department"],
                    a["asset_owner"], a["owner_email"], a["asset_value"], a["applications"])
                )
                count += 1
            except Exception:
                pass
    log_operation("asset_seed", f"初始化资产数据 {count} 条")
    return count


def calculate_risk_score(asset_value, exploitability, impact_scope):
    w = RISK_WEIGHTS
    asset_norm = min(asset_value / 10.0, 1.0)
    exploit_norm = exploitability
    impact_norm = min(impact_scope / 5.0, 1.0)
    score = (w["asset_value"] * asset_norm +
             w["exploitability"] * exploit_norm +
             w["impact_scope"] * impact_norm)
    return round(score * 100, 2)


def get_risk_level(score):
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


def correlate_threats_to_assets():
    with get_db() as conn:
        cve_intel = conn.execute(
            "SELECT * FROM threat_intel WHERE intel_type='vulnerability'").fetchall()
        assets = conn.execute("SELECT * FROM assets WHERE status='active'").fetchall()

        new_vulns = 0
        for intel in cve_intel:
            raw = json.loads(intel["raw_data"]) if intel["raw_data"] else {}
            affected_count = random.randint(1, len(assets))
            affected_assets = random.sample(assets, min(affected_count, len(assets)))
            for asset in affected_assets:
                impact_scope = random.randint(1, 5)
                score = calculate_risk_score(
                    asset["asset_value"],
                    raw.get("exploitability", 0.5),
                    impact_scope
                )
                risk_level = get_risk_level(score)
                cvss = raw.get("cvss_score", 5.0)
                exploit = raw.get("exploitability", 0.5)
                impact = cvss * 0.6
                exists = conn.execute(
                    "SELECT id FROM vulnerabilities WHERE cve_id=? AND asset_id=?",
                    (intel["indicator"], asset["id"])).fetchone()
                if not exists:
                    conn.execute(
                        """INSERT INTO vulnerabilities
                           (cve_id, asset_id, title, description, cvss_score, exploitability_score,
                            impact_score, impact_scope, risk_score, risk_level, status)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            intel["indicator"], asset["id"],
                            raw.get("title", intel["description"][:200]),
                            intel["description"],
                            cvss, exploit, impact,
                            impact_scope, score, risk_level, "open"
                        )
                    )
                    new_vulns += 1
    log_operation("threat_correlation",
                   f"威胁情报与资产关联完成，新增 {new_vulns} 个漏洞记录",
                   result=f"new_vulns={new_vulns}")
    return new_vulns


def get_asset_risk_summary():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT a.id, a.ip, a.hostname, a.department, a.asset_owner,
                   COUNT(v.id) as vuln_count,
                   ROUND(AVG(v.risk_score), 2) as avg_risk,
                   MAX(v.risk_score) as max_risk
            FROM assets a
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id AND v.status != 'fixed'
            GROUP BY a.id
            ORDER BY max_risk DESC NULLS LAST""").fetchall()
        return [dict(r) for r in rows]


def get_high_risk_assets(threshold=60):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT a.*, v.risk_score, v.cve_id, v.title as vuln_title
            FROM assets a
            JOIN vulnerabilities v ON v.asset_id = a.id
            WHERE v.risk_score >= ? AND v.status = 'open'
            ORDER BY v.risk_score DESC""", (threshold,)).fetchall()
        return [dict(r) for r in rows]
