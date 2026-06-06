import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "security_soc.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")
CACHE_DIR = os.path.join(BASE_DIR, "cache")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

for _dir in [LOG_DIR, REPORT_DIR, EXPORT_DIR, CACHE_DIR, TEMPLATES_DIR, STATIC_DIR]:
    if not os.path.exists(_dir):
        os.makedirs(_dir)

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

HTTP_RETRY = {
    "max_retries": 3,
    "backoff_factor": 2,
    "timeout": 30,
}

CACHE_TTL_HOURS = {
    "cve": 6,
    "malicious_ips": 12,
    "darkweb": 24,
}

THREAT_INTEL_SOURCES = {
    "cve": {
        "name": "CVE National Vulnerability Database",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "enabled": True,
        "results_per_page": 50,
    },
    "malicious_ips": {
        "name": "AbuseIPDB Malicious IP Blacklist",
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "enabled": True,
        "confidence_minimum": 75,
        "limit": 100,
    },
    "darkweb": {
        "name": "Dark Web Monitoring Feed",
        "url": "https://example.com/darkweb-feed",
        "enabled": True,
    },
}

RISK_WEIGHTS = {
    "asset_value": 0.4,
    "exploitability": 0.35,
    "impact_scope": 0.25,
}

TICKET_ESCALATION = {
    "start_hours": 36,
    "reminder_interval_hours": 8,
}

AUDIT_TRIGGER = {
    "consecutive_months": 2,
    "min_fix_rate": 0.75,
}

ALERT_FALSE_POSITIVE_THRESHOLD = 3

SECURITY_TEAM = [
    {"name": "张三", "email": "zhangsan@company.com", "level": "senior"},
    {"name": "李四", "email": "lisi@company.com", "level": "mid"},
    {"name": "王五", "email": "wangwu@company.com", "level": "junior"},
]

DEPARTMENT_HEADS = {
    "技术部": {"name": "赵主管", "email": "zhaosuper@company.com"},
    "运维部": {"name": "钱主管", "email": "qiansuper@company.com"},
    "市场部": {"name": "孙主管", "email": "sunsuper@company.com"},
    "财务部": {"name": "周主管", "email": "zhousuper@company.com"},
}

WEB_SERVER = {
    "host": "0.0.0.0",
    "port": 8080,
}
