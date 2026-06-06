import sqlite3
import threading
from contextlib import contextmanager
from config import DB_PATH

_local = threading.local()


def _create_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def get_db():
    owned = False
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _create_connection()
        _local.conn = conn
        owned = True
    try:
        yield conn
    except Exception:
        if owned:
            try:
                conn.rollback()
            except Exception:
                pass
        raise
    finally:
        if owned:
            try:
                conn.commit()
            except Exception:
                pass


def init_db():
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            hostname TEXT,
            os TEXT,
            department TEXT NOT NULL,
            asset_owner TEXT NOT NULL,
            owner_email TEXT NOT NULL,
            asset_value INTEGER NOT NULL DEFAULT 5,
            applications TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            intel_type TEXT NOT NULL,
            indicator TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            raw_data TEXT,
            first_seen TIMESTAMP,
            fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source, indicator)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            asset_id INTEGER NOT NULL,
            title TEXT,
            description TEXT,
            cvss_score REAL DEFAULT 0,
            exploitability_score REAL DEFAULT 0,
            impact_score REAL DEFAULT 0,
            impact_scope INTEGER DEFAULT 1,
            risk_score REAL DEFAULT 0,
            risk_level TEXT,
            status TEXT DEFAULT 'open',
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(id)
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            priority TEXT,
            assignee TEXT,
            assignee_email TEXT,
            department TEXT,
            status TEXT DEFAULT 'pending',
            difficulty TEXT DEFAULT 'medium',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            assigned_at TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            escalated_at TIMESTAMP,
            last_reminder_at TIMESTAMP,
            reminder_count INTEGER DEFAULT 0,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
            FOREIGN KEY (asset_id) REFERENCES assets(id)
        );

        CREATE TABLE IF NOT EXISTS ids_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_source TEXT,
            alert_type TEXT,
            severity TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            payload TEXT,
            alert_time TIMESTAMP NOT NULL,
            is_false_positive INTEGER DEFAULT 0,
            false_positive_count INTEGER DEFAULT 0,
            incident_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            source_ip TEXT,
            target_ip TEXT,
            login_time TIMESTAMP NOT NULL,
            success INTEGER,
            raw_log TEXT
        );

        CREATE TABLE IF NOT EXISTS network_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            flow_time TIMESTAMP NOT NULL,
            raw_flow TEXT
        );

        CREATE TABLE IF NOT EXISTS file_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_ip TEXT,
            file_path TEXT,
            action TEXT,
            change_time TIMESTAMP NOT NULL,
            file_hash TEXT,
            raw_record TEXT
        );

        CREATE TABLE IF NOT EXISTS security_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_no TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            incident_type TEXT,
            severity TEXT,
            status TEXT DEFAULT 'open',
            analyst TEXT,
            analyst_email TEXT,
            affected_assets TEXT,
            affected_data TEXT,
            attack_chain TEXT,
            mitigation TEXT,
            report_generated INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            assigned_at TIMESTAMP,
            resolved_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ioc_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            source TEXT,
            description TEXT,
            added_by TEXT DEFAULT 'system',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            incident_id INTEGER,
            UNIQUE(ioc_type, ioc_value)
        );

        CREATE TABLE IF NOT EXISTS daily_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_date DATE UNIQUE NOT NULL,
            vuln_fix_rate REAL,
            avg_response_time REAL,
            false_positive_rate REAL,
            new_vulns INTEGER,
            resolved_vulns INTEGER,
            new_incidents INTEGER,
            resolved_incidents INTEGER,
            pdf_path TEXT,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS department_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department TEXT NOT NULL,
            audit_month TEXT NOT NULL,
            vuln_fix_rate REAL,
            triggered INTEGER DEFAULT 0,
            audit_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(department, audit_month)
        );

        CREATE TABLE IF NOT EXISTS operation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator TEXT DEFAULT 'system',
            operation_type TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            description TEXT,
            result TEXT,
            ip_address TEXT,
            operation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vulnerabilities(asset_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
        CREATE INDEX IF NOT EXISTS idx_tickets_assignee ON tickets(assignee);
        CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_time ON ids_alerts(alert_time);
        CREATE INDEX IF NOT EXISTS idx_alerts_incident ON ids_alerts(incident_id);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status);
        CREATE INDEX IF NOT EXISTS idx_logs_time ON operation_logs(operation_time);
        CREATE INDEX IF NOT EXISTS idx_intel_indicator ON threat_intel(indicator);
        CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_blacklist(ioc_value);
        """)


def log_operation(operation_type, description, target_type=None, target_id=None,
                  result="success", operator="system", ip_address=None, conn=None):
    sql = """INSERT INTO operation_logs
             (operator, operation_type, target_type, target_id, description, result, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?)"""
    params = (operator, operation_type, target_type, target_id, description, result, ip_address)
    if conn is not None:
        conn.execute(sql, params)
    else:
        with get_db() as c:
            c.execute(sql, params)
