import sys
import time
import logging
from datetime import datetime
from database import init_db, get_db, log_operation
from config import LOG_DIR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/soc_system.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("SOC_SYSTEM")


def run_daily_morning_tasks():
    logger.info("===== 开始执行每日晨间任务 =====")
    log_operation("system_task_start", "每日晨间任务开始执行")

    from threat_intel import fetch_all_threat_intel
    intel_count = fetch_all_threat_intel()
    logger.info(f"威胁情报抓取完成: 新增 {intel_count} 条")

    from asset_risk import correlate_threats_to_assets
    new_vulns = correlate_threats_to_assets()
    logger.info(f"威胁情报与资产关联完成: 新增 {new_vulns} 个漏洞")

    from ticket_manager import auto_create_tickets_from_vulnerabilities
    tickets = auto_create_tickets_from_vulnerabilities()
    logger.info(f"漏洞工单自动生成完成: 新增 {tickets} 个工单")

    log_operation("system_task_complete",
                   f"每日晨间任务完成: 情报{intel_count}条, 漏洞{new_vulns}个, 工单{tickets}个")
    logger.info("===== 每日晨间任务执行完毕 =====")
    return {"intel": intel_count, "vulns": new_vulns, "tickets": tickets}


def run_realtime_tasks():
    logger.info("===== 开始执行实时处理任务 =====")
    log_operation("system_task_start", "实时告警处理任务开始执行")

    from incident_response import filter_false_positives, auto_process_real_alerts
    fp = filter_false_positives()
    logger.info(f"误报过滤完成: 过滤 {fp} 条")

    incidents = auto_process_real_alerts()
    logger.info(f"真实告警自动分配完成: 创建 {incidents} 个事件")

    from ticket_manager import escalate_overdue_tickets
    esc = escalate_overdue_tickets()
    logger.info(f"超时工单升级催办完成: 升级 {esc['escalated']}, 催办 {esc['reminded']}")

    log_operation("system_task_complete",
                   f"实时处理任务完成: 误报{fp}, 事件{incidents}, 升级{esc['escalated']}, 催办{esc['reminded']}")
    logger.info("===== 实时处理任务执行完毕 =====")
    return {"fp": fp, "incidents": incidents, "escalation": esc}


def run_daily_midnight_tasks():
    logger.info("===== 开始执行每日凌晨汇总任务 =====")
    log_operation("system_task_start", "每日凌晨汇总任务开始执行")

    from ioc_and_report import auto_generate_reports_for_resolved
    reports = auto_generate_reports_for_resolved()
    logger.info(f"已解决事件报告批量生成: {reports} 份")

    from daily_report import generate_daily_report
    report_path = generate_daily_report()
    logger.info(f"每日安全运营日报生成: {report_path}")

    from query_export import check_and_trigger_audit
    audits = check_and_trigger_audit()
    if audits:
        logger.warning(f"触发专项安全审计: {len(audits)} 个部门")
        for a in audits:
            logger.warning(f"  - {a['department']} ({a['head']}) 修复率: {a['fix_rates']}")

    log_operation("system_task_complete",
                   f"每日凌晨汇总任务完成: 报告{reports}, 审计触发{len(audits)}, 日报{report_path}")
    logger.info("===== 每日凌晨汇总任务执行完毕 =====")
    return {"reports": reports, "daily_report": report_path, "audits": audits}


def run_full_demo():
    logger.info("===== 开始执行完整演示流程 =====")
    log_operation("demo_start", "系统完整功能演示开始")

    init_db()
    logger.info("数据库初始化完成")

    from asset_risk import seed_sample_assets
    assets = seed_sample_assets()
    logger.info(f"资产数据初始化完成: {assets} 个资产")

    run_daily_morning_tasks()
    run_realtime_tasks()

    from incident_response import generate_mock_alerts, generate_mock_supporting_logs
    alerts = generate_mock_alerts(20)
    logger.info(f"生成模拟IDS告警: {alerts} 条")
    logs = generate_mock_supporting_logs()
    logger.info(f"生成模拟辅助日志: {logs}")

    run_realtime_tasks()

    with get_db() as conn:
        incidents = conn.execute(
            "SELECT id FROM security_incidents ORDER BY id DESC LIMIT 3").fetchall()
        for inc in incidents:
            from incident_response import resolve_incident
            resolve_incident(
                inc["id"],
                affected_assets="10.0.1.10, 10.0.1.20",
                affected_data="用户登录凭证, 部分数据库记录",
                attack_chain="1. 外部IP扫描端口 -> 2. 利用Web漏洞获取Shell -> "
                             "3. 提权至root -> 4. 横向移动至数据库服务器 -> 5. 数据窃取",
                mitigation="已封禁攻击源IP, 重置受影响账户密码, 修补Web漏洞, "
                           "部署WAF规则, 升级EDR检测策略",
                operator="demo_analyst"
            )
    logger.info("模拟处置完成 3 个安全事件")

    run_daily_midnight_tasks()

    from query_export import query_history, export_tickets_to_csv, export_incidents_to_csv
    q = query_history(asset_ip="10.0.1.10")
    logger.info(f"历史记录查询示例(10.0.1.10): "
                f"漏洞{len(q['vulnerabilities'])}, 告警{len(q['alerts'])}, "
                f"事件{len(q['incidents'])}, 工单{len(q['tickets'])}")

    tickets_csv = export_tickets_to_csv()
    if tickets_csv:
        logger.info(f"工单批量导出: {tickets_csv}")
    incidents_csv = export_incidents_to_csv()
    if incidents_csv:
        logger.info(f"事件报告批量导出: {incidents_csv}")

    log_operation("demo_complete", "系统完整功能演示完成")
    logger.info("===== 完整演示流程执行完毕 =====")
    print("\n" + "=" * 60)
    print("✅ 企业级安全事件自动化响应与漏洞闭环管理系统")
    print("   演示已完成！请查看以下目录：")
    print("   - 数据库: ./security_soc.db")
    print("   - 报告: ./reports/")
    print("   - 导出: ./exports/")
    print("   - 日志: ./logs/")
    print("=" * 60)


def print_help():
    print("""
企业级安全事件自动化响应与漏洞闭环管理系统

用法: python main.py <command>

命令:
  init          初始化数据库
  demo          运行完整演示流程
  morning       执行每日晨间任务 (情报抓取+关联+工单生成)
  realtime      执行实时处理任务 (误报过滤+事件分配+催办)
  midnight      执行每日凌晨汇总任务 (报告+日报+审计)
  query         历史记录查询示例
  export        批量导出工单和事件
  help          显示此帮助信息
""")


def main():
    if len(sys.argv) < 2:
        print_help()
        return

    cmd = sys.argv[1].lower()
    init_db()

    if cmd == "init":
        print("数据库初始化完成")
    elif cmd == "demo":
        run_full_demo()
    elif cmd == "morning":
        run_daily_morning_tasks()
    elif cmd == "realtime":
        run_realtime_tasks()
    elif cmd == "midnight":
        run_daily_midnight_tasks()
    elif cmd == "query":
        from query_export import query_history, get_operation_logs
        results = query_history(limit=10)
        for k, v in results.items():
            print(f"\n{k}: {len(v)} 条")
            for item in v[:3]:
                print(f"  - {item}")
        logs = get_operation_logs(limit=10)
        print(f"\n操作日志(最近10条): {len(logs)} 条")
    elif cmd == "export":
        from query_export import export_tickets_to_csv, export_incidents_to_csv
        t = export_tickets_to_csv()
        i = export_incidents_to_csv()
        print(f"工单导出: {t}\n事件导出: {i}")
    elif cmd == "help":
        print_help()
    else:
        print(f"未知命令: {cmd}")
        print_help()


if __name__ == "__main__":
    main()
