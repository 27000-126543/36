import os
import io
import json
from datetime import datetime, timedelta, date
from database import get_db, log_operation
from config import REPORT_DIR, DEPARTMENT_HEADS


def _date_range(start_date, end_date):
    for n in range(int((end_date - start_date).days) + 1):
        yield start_date + timedelta(days=n)


def _get_date_part(ts):
    if not ts:
        return None
    try:
        if isinstance(ts, date):
            return ts.strftime("%Y-%m-%d")
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d")
        if isinstance(ts, str):
            if "T" in ts:
                return ts.split("T")[0]
            if " " in ts:
                return ts.split(" ")[0]
            return ts[:10]
    except Exception:
        return None
    return None


def calculate_metrics_for_date(target_date):
    start = datetime.combine(target_date, datetime.min.time())
    end = start + timedelta(days=1)
    start_s = start.isoformat()
    end_s = end.isoformat()
    metrics = {
        "new_vulns": 0,
        "resolved_vulns": 0,
        "new_incidents": 0,
        "resolved_incidents": 0,
        "new_alerts": 0,
        "fp_alerts": 0,
        "avg_response_time": 0.0,
        "vuln_fix_rate": 0.0,
        "false_positive_rate": 0.0,
    }

    with get_db() as conn:
        metrics["new_vulns"] = conn.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE discovered_at >= ? AND discovered_at < ?",
            (start_s, end_s)).fetchone()["c"]

        metrics["resolved_vulns"] = conn.execute(
            """SELECT COUNT(*) as c FROM vulnerabilities v
               JOIN tickets t ON t.vuln_id = v.id
               WHERE t.status='completed' AND t.completed_at >= ? AND t.completed_at < ?""",
            (start_s, end_s)).fetchone()["c"]

        metrics["new_incidents"] = conn.execute(
            "SELECT COUNT(*) as c FROM security_incidents WHERE created_at >= ? AND created_at < ?",
            (start_s, end_s)).fetchone()["c"]

        resolved_incidents = conn.execute(
            """SELECT * FROM security_incidents
               WHERE status='resolved' AND resolved_at >= ? AND resolved_at < ?""",
            (start_s, end_s)).fetchall()
        metrics["resolved_incidents"] = len(resolved_incidents)

        rts = []
        for i in resolved_incidents:
            if i["assigned_at"] and i["resolved_at"]:
                try:
                    rt = (datetime.fromisoformat(i["resolved_at"]) -
                          datetime.fromisoformat(i["assigned_at"])).total_seconds() / 3600.0
                    if rt >= 0:
                        rts.append(rt)
                except Exception:
                    pass
        metrics["avg_response_time"] = round(sum(rts) / len(rts), 2) if rts else 0.0

        metrics["new_alerts"] = conn.execute(
            "SELECT COUNT(*) as c FROM ids_alerts WHERE alert_time >= ? AND alert_time < ?",
            (start_s, end_s)).fetchone()["c"]

        metrics["fp_alerts"] = conn.execute(
            "SELECT COUNT(*) as c FROM ids_alerts WHERE alert_time >= ? AND alert_time < ? AND is_false_positive=1",
            (start_s, end_s)).fetchone()["c"]

        metrics["false_positive_rate"] = (
            round(metrics["fp_alerts"] / metrics["new_alerts"], 4)
            if metrics["new_alerts"] > 0 else 0.0
        )

        total_vulns = conn.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE discovered_at < ?", (end_s,)).fetchone()["c"]
        fixed_vulns = conn.execute(
            """SELECT COUNT(*) as c FROM vulnerabilities v
               JOIN tickets t ON t.vuln_id = v.id
               WHERE t.status='completed' AND t.completed_at < ?""",
            (end_s,)).fetchone()["c"]
        metrics["vuln_fix_rate"] = round(fixed_vulns / total_vulns, 4) if total_vulns > 0 else 0.0

    return metrics


def calculate_trend_metrics(end_date, days=7):
    trend = []
    for i in range(days - 1, -1, -1):
        d = end_date - timedelta(days=i)
        m = calculate_metrics_for_date(d)
        m["date"] = d.strftime("%Y-%m-%d")
        m["date_label"] = d.strftime("%m-%d")
        trend.append(m)
    return trend


def _plot_trend_matplotlib(trend_data, output_path, title, value_key, y_label, color="#3498db"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None

    labels = [d["date_label"] for d in trend_data]
    values = [d.get(value_key, 0) for d in trend_data]

    plt.figure(figsize=(8, 4))
    plt.bar(labels, values, color=color)
    plt.title(title, fontsize=14, fontweight="bold")
    plt.xlabel("日期")
    plt.ylabel(y_label)
    plt.xticks(rotation=30, fontsize=9)
    for i, v in enumerate(values):
        plt.text(i, v, str(v), ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_path, format="png", dpi=120)
    plt.close()
    return output_path


def _plot_line_matplotlib(trend_data, output_path, title, value_key, y_label, color="#e74c3c"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None

    labels = [d["date_label"] for d in trend_data]
    values = [round(d.get(value_key, 0) * 100, 1) for d in trend_data]

    plt.figure(figsize=(8, 4))
    plt.plot(labels, values, marker="o", color=color, linewidth=2)
    plt.fill_between(labels, values, alpha=0.2, color=color)
    plt.title(title, fontsize=14, fontweight="bold")
    plt.xlabel("日期")
    plt.ylabel(y_label)
    plt.xticks(rotation=30, fontsize=9)
    for i, v in enumerate(values):
        plt.text(i, v, f"{v}%", ha="center", va="bottom", fontsize=9)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, format="png", dpi=120)
    plt.close()
    return output_path


def generate_pdf_report(report_date=None):
    if report_date is None:
        report_date = datetime.now().date()
    date_str = report_date.strftime("%Y-%m-%d")

    today_metrics = calculate_metrics_for_date(report_date)
    trend = calculate_trend_metrics(report_date, days=7)

    chart_dir = os.path.join(REPORT_DIR, "charts")
    os.makedirs(chart_dir, exist_ok=True)

    vuln_chart = _plot_trend_matplotlib(
        trend,
        os.path.join(chart_dir, f"vuln_trend_{date_str}.png"),
        "近7日新增漏洞趋势", "new_vulns", "数量", "#3498db"
    )
    incident_chart = _plot_trend_matplotlib(
        trend,
        os.path.join(chart_dir, f"incident_trend_{date_str}.png"),
        "近7日新增安全事件趋势", "new_incidents", "数量", "#27ae60"
    )
    fp_chart = _plot_line_matplotlib(
        trend,
        os.path.join(chart_dir, f"fp_trend_{date_str}.png"),
        "近7日误报率趋势", "false_positive_rate", "百分比(%)", "#e67e22"
    )
    response_chart = _plot_trend_matplotlib(
        trend,
        os.path.join(chart_dir, f"response_trend_{date_str}.png"),
        "近7日平均告警处置时长(h)", "avg_response_time", "小时", "#9b59b6"
    )

    report_json = {
        "report_date": date_str,
        "metrics": today_metrics,
        "trend": trend,
        "generated_at": datetime.now().isoformat(),
    }
    json_path = os.path.join(REPORT_DIR, f"daily_report_{date_str}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_json, f, ensure_ascii=False, indent=2)

    html_path = _generate_html_report(report_date, today_metrics, trend,
                                      vuln_chart, incident_chart, fp_chart, response_chart)

    pdf_path = os.path.join(REPORT_DIR, f"daily_report_{date_str}.pdf")
    try:
        _build_pdf_with_reportlab(
            pdf_path, report_date, today_metrics, trend,
            vuln_chart, incident_chart, fp_chart, response_chart
        )
    except Exception as e:
        log_operation("daily_report_pdf_error",
                       f"生成 PDF 失败: {e}，将使用 HTML 替代",
                       result="pdf_failed")
        pdf_path = html_path

    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM daily_reports WHERE report_date=?", (date_str,)).fetchone()
        if existing:
            conn.execute(
                """UPDATE daily_reports
                   SET vuln_fix_rate=?, avg_response_time=?, false_positive_rate=?,
                       new_vulns=?, resolved_vulns=?, new_incidents=?, resolved_incidents=?,
                       pdf_path=?, generated_at=? WHERE id=?""",
                (today_metrics["vuln_fix_rate"], today_metrics["avg_response_time"],
                 today_metrics["false_positive_rate"], today_metrics["new_vulns"],
                 today_metrics["resolved_vulns"], today_metrics["new_incidents"],
                 today_metrics["resolved_incidents"], pdf_path,
                 datetime.now().isoformat(), existing["id"])
            )
        else:
            conn.execute(
                """INSERT INTO daily_reports
                   (report_date, vuln_fix_rate, avg_response_time, false_positive_rate,
                    new_vulns, resolved_vulns, new_incidents, resolved_incidents, pdf_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (date_str, today_metrics["vuln_fix_rate"], today_metrics["avg_response_time"],
                 today_metrics["false_positive_rate"], today_metrics["new_vulns"],
                 today_metrics["resolved_vulns"], today_metrics["new_incidents"],
                 today_metrics["resolved_incidents"], pdf_path)
            )

    log_operation("daily_report_generate",
                   f"生成 {date_str} 安全运营日报: {pdf_path}",
                   target_type="report", result=f"path={pdf_path}")
    _push_report_to_stakeholders(pdf_path, date_str)
    return pdf_path


def _generate_html_report(report_date, metrics, trend, v_chart, i_chart, f_chart, r_chart):
    date_str = report_date.strftime("%Y-%m-%d")
    def _img(p):
        if p and os.path.exists(p):
            import base64
            with open(p, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            return f'<img src="data:image/png;base64,{data}" style="max-width:100%;"/>'
        return "<p style='color:#999;'>图表不可用</p>"

    with get_db() as conn:
        top_tickets = conn.execute(
            """SELECT t.id, t.title, t.priority, a.department, t.assignee, t.created_at
               FROM tickets t JOIN assets a ON a.id = t.asset_id
               WHERE t.status != 'completed'
               ORDER BY CASE t.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2
                         WHEN 'medium' THEN 3 ELSE 4 END, t.created_at LIMIT 10""").fetchall()

    html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<title>安全运营日报 - {date_str}</title>
<style>
body{{font-family:"Microsoft YaHei",Arial,sans-serif;margin:40px;color:#333;}}
h1{{text-align:center;color:#2c3e50;}}
.metrics{{display:flex;flex-wrap:wrap;gap:20px;margin:30px 0;}}
.metric-card{{flex:1;min-width:180px;padding:20px;border-radius:8px;background:#f8f9fa;border-left:4px solid #3498db;}}
.metric-card h3{{margin:0 0 10px;color:#7f8c8d;font-size:14px;}}
.metric-card .value{{font-size:26px;font-weight:bold;color:#2c3e50;}}
.section{{margin:30px 0;}}
.section h2{{color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:8px;}}
table{{width:100%;border-collapse:collapse;margin-top:15px;}}
th,td{{padding:10px;text-align:left;border-bottom:1px solid #ddd;}}
th{{background:#34495e;color:white;}}
.footer{{text-align:center;color:#999;margin-top:40px;font-size:12px;}}
</style></head><body>
<h1>企业安全运营日报</h1>
<p style="text-align:center;color:#7f8c8d;">报告日期: {date_str} | 生成时间: {datetime.now().isoformat()}</p>
<div class="section"><h2>一、核心指标概览</h2><div class="metrics">
<div class="metric-card"><h3>漏洞修复率</h3><div class="value">{metrics['vuln_fix_rate']*100:.1f}%</div></div>
<div class="metric-card"><h3>平均处置时长</h3><div class="value">{metrics['avg_response_time']:.2f}h</div></div>
<div class="metric-card"><h3>误报率</h3><div class="value">{metrics['false_positive_rate']*100:.1f}%</div></div>
<div class="metric-card"><h3>新增漏洞</h3><div class="value">{metrics['new_vulns']}</div></div>
<div class="metric-card"><h3>已修复漏洞</h3><div class="value">{metrics['resolved_vulns']}</div></div>
<div class="metric-card"><h3>新增事件</h3><div class="value">{metrics['new_incidents']}</div></div>
<div class="metric-card"><h3>已处置事件</h3><div class="value">{metrics['resolved_incidents']}</div></div>
<div class="metric-card"><h3>新增告警</h3><div class="value">{metrics['new_alerts']}</div></div>
</div></div>
<div class="section"><h2>二、趋势分析</h2>
{_img(v_chart)}<br><br>
{_img(i_chart)}<br><br>
{_img(f_chart)}<br><br>
{_img(r_chart)}
</div>
<div class="section"><h2>三、待处理高风险工单 TOP 10</h2>
<table><tr><th>工单ID</th><th>标题</th><th>优先级</th><th>部门</th><th>处理人</th><th>创建时间</th></tr>"""
    if top_tickets:
        for t in top_tickets:
            html += f"""<tr><td>#{t['id']}</td><td>{t['title']}</td>
<td>{t['priority']}</td><td>{t['department']}</td><td>{t['assignee']}</td>
<td>{t['created_at']}</td></tr>"""
    else:
        html += "<tr><td colspan='6' style='text-align:center;color:#999;'>暂无待处理工单</td></tr>"
    html += f"""</table></div>
<div class="footer"><p>本报告由企业级安全事件自动化响应与漏洞闭环管理系统自动生成</p>
<p>© {datetime.now().year} 企业安全运营中心</p></div></body></html>"""

    html_path = os.path.join(REPORT_DIR, f"daily_report_{date_str}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    return html_path


def _build_pdf_with_reportlab(pdf_path, report_date, metrics, trend,
                              v_chart, i_chart, f_chart, r_chart):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
    )
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font_paths = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/Library/Fonts/Songti.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    font_name = "Helvetica"
    for fp in font_paths:
        if os.path.exists(fp):
            try:
                pdfmetrics.registerFont(TTFont("CNFont", fp))
                font_name = "CNFont"
                break
            except Exception:
                continue

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], fontName=font_name, fontSize=20,
        alignment=1, spaceAfter=12, textColor=colors.HexColor("#2c3e50"))
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontName=font_name, fontSize=14,
        spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#2c3e50"),
        borderWidth=0, borderPadding=0)
    normal = ParagraphStyle(
        "Body", parent=styles["Normal"], fontName=font_name, fontSize=10, leading=14)
    small = ParagraphStyle(
        "Small", parent=styles["Normal"], fontName=font_name, fontSize=9, leading=12,
        textColor=colors.grey)

    story = []
    date_str = report_date.strftime("%Y-%m-%d")

    story.append(Paragraph("企业安全运营日报", title_style))
    story.append(Paragraph(f"报告日期: {date_str} &nbsp;&nbsp; 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                           ParagraphStyle("center", parent=normal, alignment=1)))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("一、核心指标概览", h2))
    metric_items = [
        ("漏洞修复率", f"{metrics['vuln_fix_rate']*100:.1f}%"),
        ("平均处置时长", f"{metrics['avg_response_time']:.2f}h"),
        ("误报率", f"{metrics['false_positive_rate']*100:.1f}%"),
        ("新增漏洞", str(metrics['new_vulns'])),
        ("已修复漏洞", str(metrics['resolved_vulns'])),
        ("新增事件", str(metrics['new_incidents'])),
        ("已处置事件", str(metrics['resolved_incidents'])),
        ("新增告警", str(metrics['new_alerts'])),
    ]
    table_data = []
    for i in range(0, len(metric_items), 4):
        row = []
        for name, val in metric_items[i:i+4]:
            row.append(Paragraph(f"<b>{name}</b><br/><font size='14' color='#2c3e50'>{val}</font>", normal))
        while len(row) < 4:
            row.append("")
        table_data.append(row)

    tbl = Table(table_data, colWidths=[4.2*cm]*4)
    tbl.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#ecf0f1")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.4*cm))

    def _add_chart(title, path):
        story.append(Paragraph(title, h2))
        if path and os.path.exists(path):
            story.append(Image(path, width=16*cm, height=8*cm))
        else:
            story.append(Paragraph("图表不可用", small))

    _add_chart("二、近7日新增漏洞趋势", v_chart)
    story.append(Spacer(1, 0.3*cm))
    _add_chart("三、近7日新增安全事件趋势", i_chart)
    story.append(PageBreak())
    _add_chart("四、近7日误报率趋势(%)", f_chart)
    story.append(Spacer(1, 0.3*cm))
    _add_chart("五、近7日平均告警处置时长(h)", r_chart)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("六、待处理高风险工单 TOP 10", h2))
    with get_db() as conn:
        top_tickets = conn.execute(
            """SELECT t.id, t.title, t.priority, a.department, t.assignee, t.created_at
               FROM tickets t JOIN assets a ON a.id = t.asset_id
               WHERE t.status != 'completed'
               ORDER BY CASE t.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2
                         WHEN 'medium' THEN 3 ELSE 4 END, t.created_at LIMIT 10""").fetchall()
    header = [Paragraph("<b>工单ID</b>", normal),
              Paragraph("<b>标题</b>", normal),
              Paragraph("<b>优先级</b>", normal),
              Paragraph("<b>部门</b>", normal),
              Paragraph("<b>处理人</b>", normal),
              Paragraph("<b>创建时间</b>", normal)]
    rows = [header]
    for t in top_tickets:
        rows.append([
            Paragraph(f"#{t['id']}", normal),
            Paragraph((t['title'] or "")[:50], normal),
            Paragraph(t['priority'] or "", normal),
            Paragraph(t['department'] or "", normal),
            Paragraph(t['assignee'] or "", normal),
            Paragraph((t['created_at'] or "")[:16], normal),
        ])
    if not top_tickets:
        rows.append([Paragraph("暂无待处理工单",
                               ParagraphStyle("ce", parent=normal, alignment=1))] + [""] * 5)

    ttbl = Table(rows, colWidths=[1.5*cm, 6*cm, 2*cm, 2.5*cm, 2*cm, 3*cm])
    ttbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bdc3c7")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(ttbl)
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        f"本报告由企业级安全事件自动化响应与漏洞闭环管理系统自动生成 &nbsp;&nbsp; © {datetime.now().year} 企业安全运营中心",
        ParagraphStyle("footer", parent=small, alignment=1)))

    doc.build(story)


def _push_report_to_stakeholders(report_path, date_str):
    recipients = []
    for dept, head in DEPARTMENT_HEADS.items():
        recipients.append(f"{head['name']} <{head['email']}>")
    recipients.append(f"安全运营负责人 <soc-lead@company.com>")
    log_operation("daily_report_push",
                   f"{date_str} 日报已推送至 {len(recipients)} 位负责人",
                   target_type="report", result=f"recipients={len(recipients)}")
    return recipients


def generate_daily_report(report_date=None):
    return generate_pdf_report(report_date)
