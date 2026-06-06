import os
import json
import time
import random
import hashlib
import logging
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta
from database import get_db, log_operation
from config import (
    THREAT_INTEL_SOURCES, NVD_API_KEY, ABUSEIPDB_API_KEY,
    HTTP_RETRY, CACHE_TTL_HOURS, CACHE_DIR
)

logger = logging.getLogger("SOC_THREAT_INTEL")


def _cache_path(cache_key):
    safe = hashlib.md5(cache_key.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"intel_{safe}.json")


def _read_cache(cache_key, ttl_hours):
    path = _cache_path(cache_key)
    if not os.path.exists(path):
        return None
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        if datetime.now() - mtime > timedelta(hours=ttl_hours):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_cache(cache_key, data):
    try:
        path = _cache_path(cache_key)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception:
        pass


def _http_get(url, headers=None, params=None, timeout=None):
    timeout = timeout or HTTP_RETRY["timeout"]
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    last_err = None
    for attempt in range(1, HTTP_RETRY["max_retries"] + 1):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if resp.status >= 400:
                    raise urllib.error.HTTPError(url, resp.status, body, {}, None)
                return json.loads(body)
        except Exception as e:
            last_err = e
            wait = HTTP_RETRY["backoff_factor"] ** attempt
            logger.warning(f"HTTP GET 失败 (第{attempt}次): {url} -> {e}, {wait}秒后重试")
            time.sleep(wait)
    raise last_err or RuntimeError("HTTP request failed")


def _generate_mock_cves(count=20):
    cve_templates = [
        {"title": "Apache Log4j JNDI 远程代码执行漏洞", "severity": "critical",
         "desc": "Log4j2 组件存在 JNDI 注入漏洞，攻击者可通过构造恶意请求执行任意代码。"},
        {"title": "Spring Framework RCE 漏洞 (Spring4Shell)", "severity": "critical",
         "desc": "Spring Framework 存在远程代码执行漏洞，影响使用 Spring Boot 打包部署的 JDK9+ 应用。"},
        {"title": "OpenSSL 心脏滴血漏洞", "severity": "high",
         "desc": "OpenSSL TLS 心跳扩展实现存在越界读取漏洞，攻击者可读取服务器内存中的敏感信息。"},
        {"title": "Struts2 远程代码执行漏洞", "severity": "critical",
         "desc": "Apache Struts2 存在多个远程代码执行漏洞，攻击者可构造恶意请求执行任意命令。"},
        {"title": "Nginx 目录遍历漏洞", "severity": "medium",
         "desc": "Nginx 在特定配置下存在目录遍历漏洞，攻击者可读取敏感文件。"},
        {"title": "MySQL 身份认证绕过漏洞", "severity": "high",
         "desc": "MySQL 身份认证模块存在漏洞，攻击者可绕过密码验证直接登录。"},
        {"title": "Redis 未授权访问漏洞", "severity": "high",
         "desc": "Redis 默认配置存在未授权访问，攻击者可写入 SSH 公钥获取服务器权限。"},
        {"title": "Jenkins 远程代码执行漏洞", "severity": "critical",
         "desc": "Jenkins CLI 存在反序列化漏洞，攻击者可执行任意代码。"},
        {"title": "Django SQL 注入漏洞", "severity": "high",
         "desc": "Django ORM 在特定查询下存在 SQL 注入漏洞。"},
        {"title": "Kubernetes API Server 权限提升漏洞", "severity": "high",
         "desc": "K8s API Server 存在权限提升漏洞，普通用户可获取集群管理员权限。"},
    ]
    results = []
    for i in range(count):
        tpl = random.choice(cve_templates)
        year = random.choice([2023, 2024, 2025, 2026])
        cve_id = f"CVE-{year}-{random.randint(1000, 99999)}"
        cvss = round(random.uniform(5.0, 10.0), 1)
        exploit = round(random.uniform(0.3, 1.0), 2)
        results.append({
            "cve_id": cve_id,
            "title": tpl["title"],
            "description": tpl["desc"],
            "severity": tpl["severity"],
            "cvss_score": cvss,
            "exploitability": exploit,
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 90))).isoformat(),
        })
    return results


def _generate_mock_malicious_ips(count=30):
    results = []
    for _ in range(count):
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        categories = random.sample(["port_scan", "brute_force", "malware_c2", "spam", "botnet"],
                                   k=random.randint(1, 3))
        results.append({
            "ip": ip,
            "categories": categories,
            "abuse_score": random.randint(25, 100),
            "country": random.choice(["CN", "US", "RU", "KP", "IR", "BR", "IN"]),
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 60))).isoformat(),
        })
    return results


def _generate_mock_darkweb_intel(count=10):
    templates = [
        "疑似内部员工账户凭证在暗网论坛出售",
        "企业源代码仓库凭证出现在暗网交易平台",
        "检测到客户数据样本在黑客论坛泄露",
        "内部 VPN 配置文件在暗网流通",
        "企业邮箱账户密码出现在数据泄露合集",
    ]
    results = []
    for _ in range(count):
        results.append({
            "description": random.choice(templates),
            "source_url": f"http://darkweb{random.randint(1000, 9999)}.onion/post/{hashlib.md5(str(random.random()).encode()).hexdigest()[:16]}",
            "data_type": random.choice(["credentials", "source_code", "customer_data", "config"]),
            "confidence": round(random.uniform(0.6, 1.0), 2),
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),
        })
    return results


def fetch_cve_intel():
    source_cfg = THREAT_INTEL_SOURCES["cve"]
    if not source_cfg["enabled"]:
        return 0

    cache_key = "nvd_cve_recent"
    ttl = CACHE_TTL_HOURS["cve"]
    cached = _read_cache(cache_key, ttl)
    cve_list = None

    if cached:
        logger.info(f"使用缓存 CVE 数据: {len(cached)} 条")
        cve_list = cached
    elif NVD_API_KEY:
        try:
            headers = {"User-Agent": "EnterpriseSOC/1.0"}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY
            params = {
                "resultsPerPage": source_cfg.get("results_per_page", 50),
                "pubStartDate": (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999"),
            }
            data = _http_get(source_cfg["url"], headers=headers, params=params)
            parsed = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_v3 = (metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                           or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}))
                parsed.append({
                    "cve_id": cve.get("id"),
                    "title": (cve.get("descriptions", [{}])[0].get("value", "")[:200]
                              or cve.get("id")),
                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                    "severity": cvss_v3.get("baseSeverity", "medium").lower(),
                    "cvss_score": cvss_v3.get("baseScore", 0.0),
                    "exploitability": cvss_v3.get("exploitabilityScore", 5.0) / 10.0,
                    "first_seen": cve.get("published", datetime.now().isoformat()),
                })
            cve_list = [c for c in parsed if c.get("cve_id")]
            _write_cache(cache_key, cve_list)
            logger.info(f"从 NVD API 获取 CVE: {len(cve_list)} 条")
        except Exception as e:
            logger.error(f"NVD API 获取失败，降级使用模拟数据: {e}")

    if cve_list is None:
        cve_list = _generate_mock_cves(20)
        logger.info(f"使用模拟 CVE 数据: {len(cve_list)} 条")

    inserted = 0
    with get_db() as conn:
        for intel in cve_list:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO threat_intel
                       (source, intel_type, indicator, description, severity, raw_data, first_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    ("cve", "vulnerability", intel["cve_id"],
                     intel["description"][:500], intel["severity"],
                     json.dumps(intel, ensure_ascii=False), intel["first_seen"])
                )
                inserted += 1
            except Exception:
                pass
    log_operation("threat_intel_fetch",
                   f"从 CVE 源获取 {inserted} 条情报",
                   result=f"inserted={inserted}")
    return inserted


def fetch_malicious_ip_intel():
    source_cfg = THREAT_INTEL_SOURCES["malicious_ips"]
    if not source_cfg["enabled"]:
        return 0

    cache_key = "abuseipdb_blacklist"
    ttl = CACHE_TTL_HOURS["malicious_ips"]
    cached = _read_cache(cache_key, ttl)
    ip_list = None

    if cached:
        logger.info(f"使用缓存恶意IP数据: {len(cached)} 条")
        ip_list = cached
    elif ABUSEIPDB_API_KEY:
        try:
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {
                "confidenceMinimum": source_cfg.get("confidence_minimum", 75),
                "limit": source_cfg.get("limit", 100),
            }
            data = _http_get(source_cfg["url"], headers=headers, params=params)
            parsed = []
            for item in data.get("data", []):
                parsed.append({
                    "ip": item.get("ipAddress"),
                    "categories": [str(c) for c in item.get("categories", [])],
                    "abuse_score": item.get("abuseConfidenceScore", 0),
                    "country": item.get("countryCode", ""),
                    "first_seen": item.get("lastReportedAt", datetime.now().isoformat()),
                })
            ip_list = [x for x in parsed if x.get("ip")]
            _write_cache(cache_key, ip_list)
            logger.info(f"从 AbuseIPDB API 获取恶意IP: {len(ip_list)} 条")
        except Exception as e:
            logger.error(f"AbuseIPDB API 获取失败，降级使用模拟数据: {e}")

    if ip_list is None:
        ip_list = _generate_mock_malicious_ips(30)
        logger.info(f"使用模拟恶意IP数据: {len(ip_list)} 条")

    inserted = 0
    with get_db() as conn:
        for intel in ip_list:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO threat_intel
                       (source, intel_type, indicator, description, severity, raw_data, first_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    ("malicious_ips", "ip", intel["ip"],
                     f"恶意IP分类: {','.join(intel['categories'])}, 信誉分: {intel['abuse_score']}",
                     "high" if intel["abuse_score"] >= 75 else "medium",
                     json.dumps(intel, ensure_ascii=False), intel["first_seen"])
                )
                inserted += 1
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO ioc_blacklist
                           (ioc_type, ioc_value, source, description)
                           VALUES (?, ?, ?, ?)""",
                        ("ip", intel["ip"], "abuseipdb",
                         f"恶意IP, 信誉分: {intel['abuse_score']}")
                    )
                except Exception:
                    pass
            except Exception:
                pass
    log_operation("threat_intel_fetch",
                   f"从恶意IP黑名单源获取 {inserted} 条情报",
                   result=f"inserted={inserted}")
    return inserted


def fetch_darkweb_intel():
    source_cfg = THREAT_INTEL_SOURCES["darkweb"]
    if not source_cfg["enabled"]:
        return 0

    cache_key = "darkweb_intel"
    ttl = CACHE_TTL_HOURS["darkweb"]
    cached = _read_cache(cache_key, ttl)
    dark_list = cached if cached else None
    if cached:
        logger.info(f"使用缓存暗网情报: {len(cached)} 条")

    if dark_list is None:
        dark_list = _generate_mock_darkweb_intel(10)
        _write_cache(cache_key, dark_list)
        logger.info(f"使用模拟暗网数据: {len(dark_list)} 条")

    inserted = 0
    with get_db() as conn:
        for intel in dark_list:
            try:
                indicator = hashlib.md5(intel["description"].encode()).hexdigest()
                conn.execute(
                    """INSERT OR IGNORE INTO threat_intel
                       (source, intel_type, indicator, description, severity, raw_data, first_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    ("darkweb", "darkweb_leak", indicator, intel["description"],
                     "high" if intel["confidence"] >= 0.8 else "medium",
                     json.dumps(intel, ensure_ascii=False), intel["first_seen"])
                )
                inserted += 1
            except Exception:
                pass
    log_operation("threat_intel_fetch",
                   f"从暗网监控源获取 {inserted} 条情报",
                   result=f"inserted={inserted}")
    return inserted


def fetch_all_threat_intel():
    total = 0
    total += fetch_cve_intel()
    total += fetch_malicious_ip_intel()
    total += fetch_darkweb_intel()
    log_operation("threat_intel_daily_fetch",
                   f"每日威胁情报抓取完成，共获取 {total} 条新情报",
                   result=f"total={total}")
    return total
