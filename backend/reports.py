"""HTML/PDF/remediation report generation. Moved verbatim out of app.py
(Phase 1 package split), except that `app.config['REPORT_FOLDER']` is now
`Config.REPORT_FOLDER` since these functions no longer have access to the
global Flask `app` object directly."""
import os
import re
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)

from config import Config

def generate_html_report(results, overall_score, policy_name, framework_info, report_id):
    timestamp = datetime.now()
    filename = (
        f"Audinexia_Report_{framework_info['name'].replace(' ', '_')}"
        f"_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"
    )
    filepath = os.path.join(Config.REPORT_FOLDER, filename)

    compliant     = sum(1 for r in results if r['status'] == 'Compliant')
    partial       = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant = sum(1 for r in results if r['status'] == 'Non-Compliant')
    high_risk     = sum(1 for r in results if r['risk_level'] == 'High')

    if overall_score >= 80:
        score_color = "#10b981"; score_label = "COMPLIANT"
    elif overall_score >= 50:
        score_color = "#f59e0b"; score_label = "PARTIAL"
    else:
        score_color = "#ef4444"; score_label = "NON-COMPLIANT"

    control_cards = ""
    for c in results:
        border = "#ef4444" if c['risk_level'] == 'High' else ("#f59e0b" if c['risk_level'] == 'Medium' else "#10b981")
        found_html   = "".join(f'<span class="tag tag-found">{p}</span>' for p in c['found_phrases']) or '<em style="color:#9ca3af">None</em>'
        missing_html = "".join(f'<span class="tag tag-miss">{p}</span>'  for p in c['missing_phrases']) or '<em style="color:#9ca3af">None</em>'
        ev = ""
        if c['evidence']:
            ev_text = c['evidence'][:200] + ("…" if len(c['evidence']) > 200 else "")
            ev = f'<div class="evidence-box">📄 <strong>Evidence:</strong> <em>"{ev_text}"</em></div>'
        bar_color = "#10b981" if c['score'] >= 80 else ("#f59e0b" if c['score'] >= 50 else "#ef4444")
        control_cards += f"""
        <div class="card" style="border-left:4px solid {border}">
          <div class="card-header"><div><span class="ctrl-id">{c['id']}</span><span class="ctrl-name">{c['name']}</span></div>
            <span class="risk-badge" style="background:{'#fef2f2' if c['risk_level']=='High' else ('#fffbeb' if c['risk_level']=='Medium' else '#f0fdf4')};color:{border};border:1px solid {border}">{c['symbol']} {c['status']}</span></div>
          <div class="meta-row"><span>📋 {c['clause']}</span><span>👤 {c['owner']}</span><span>⚡ {c['severity'].capitalize()}</span><span>⚖️ Weight: {c['weight']}</span></div>
          <div class="score-bar-wrap"><div class="score-bar-track"><div class="score-bar-fill" style="width:{c['score']}%;background:{bar_color}"></div></div><span class="score-num" style="color:{bar_color}">{c['score']}%</span></div>
          <div class="phrase-grid"><div class="phrase-col"><div class="phrase-label">✅ Found</div><div>{found_html}</div></div><div class="phrase-col"><div class="phrase-label">❌ Missing</div><div>{missing_html}</div></div></div>
          {ev}
          <div class="why-box"><strong>⚠️ Why it matters:</strong> {c['why_matters']}</div>
          <div class="fix-box"><strong>🔧 Recommended Fix:</strong> {c['fix_suggestion']}</div>
        </div>"""

    sum_rows = ""
    for c in results:
        pill_cls = 'pill-green' if c['status'] == 'Compliant' else ('pill-yellow' if c['status'] == 'Partially Compliant' else 'pill-red')
        bar_c = "#10b981" if c['score'] >= 80 else ("#f59e0b" if c['score'] >= 50 else "#ef4444")
        risk_c = "#ef4444" if c['risk_level'] == 'High' else ("#f59e0b" if c['risk_level'] == 'Medium' else "#10b981")
        sum_rows += f"""<tr><td><code style="font-size:11px;background:#f1f5f9;padding:2px 6px;border-radius:4px">{c['id']}</code></td><td style="font-weight:600">{c['name']}</td><td style="color:#64748b;font-size:12px">{c['clause']}</td><td style="color:#64748b;font-size:12px">{c['owner']}</td><td style="font-size:12px;font-weight:600">{c['severity'].capitalize()}</td>
          <td><span style="display:inline-block;width:70px;height:6px;background:#f1f5f9;border-radius:99px;vertical-align:middle;overflow:hidden"><span style="display:block;width:{c['score']}%;height:100%;background:{bar_c};border-radius:99px"></span></span><span style="font-size:12px;font-weight:600;color:{bar_c};margin-left:6px">{c['score']}%</span></td>
          <td><span class="pill {pill_cls}">{c['symbol']} {c['status']}</span></td><td style="font-weight:700;color:{risk_c}">{c['risk_level']}</td></tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audinexia - {framework_info['name']} Compliance Report</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f0f4f8;color:#1e293b;font-size:14px}}
  .page{{max-width:1080px;margin:32px auto;background:#fff;border-radius:20px;box-shadow:0 8px 40px rgba(0,0,0,.10);overflow:hidden}}
  .header{{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 60%,#164e63 100%);padding:40px 48px 32px;color:#fff;position:relative}}
  .header::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:4px;background:linear-gradient(90deg,#3b82f6,#06b6d4,#10b981)}}
  .brand{{display:flex;align-items:center;gap:12px;margin-bottom:28px}}
  .brand-name{{font-size:22px;font-weight:800;letter-spacing:1.5px;color:#38bdf8}}
  .brand-tag{{font-size:11px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase}}
  .header-title{{font-size:28px;font-weight:700;margin-bottom:6px}}
  .header-sub{{font-size:13px;color:#94a3b8}}
  .meta-chips{{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}}
  .chip{{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);border-radius:20px;padding:4px 14px;font-size:12px;color:#e2e8f0}}
  .score-band{{background:#f8fafc;border-bottom:1px solid #e2e8f0;padding:32px 48px;display:flex;align-items:center;gap:48px;flex-wrap:wrap}}
  .stat-grid{{display:flex;gap:20px;flex-wrap:wrap;flex:1}}
  .stat-box{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px 24px;min-width:110px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.04)}}
  .stat-num{{font-size:32px;font-weight:800}}.stat-lbl{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:2px}}
  .section{{padding:32px 48px}}
  .section-title{{font-size:18px;font-weight:700;color:#0f172a;border-bottom:2px solid #e2e8f0;padding-bottom:10px;margin-bottom:24px}}
  .summary-table{{width:100%;border-collapse:collapse;font-size:13px}}
  .summary-table th{{background:#f1f5f9;text-align:left;padding:10px 14px;font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#64748b;border-bottom:2px solid #e2e8f0}}
  .summary-table td{{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:middle}}
  .summary-table tr:hover td{{background:#fafbfc}}
  .pill{{display:inline-block;border-radius:20px;padding:3px 12px;font-size:11px;font-weight:600}}
  .pill-green{{background:#d1fae5;color:#065f46}}.pill-yellow{{background:#fef3c7;color:#92400e}}.pill-red{{background:#fee2e2;color:#991b1b}}
  .card{{border-radius:12px;background:#fff;border:1px solid #e2e8f0;border-left-width:4px;padding:20px 24px;margin-bottom:18px;box-shadow:0 2px 8px rgba(0,0,0,.04)}}
  .card-header{{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:10px}}
  .ctrl-id{{font-size:11px;font-weight:700;color:#64748b;background:#f1f5f9;padding:2px 8px;border-radius:6px;margin-right:8px}}
  .ctrl-name{{font-size:15px;font-weight:700;color:#0f172a}}
  .risk-badge{{font-size:12px;font-weight:600;padding:4px 12px;border-radius:20px;white-space:nowrap}}
  .meta-row{{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:#64748b;margin-bottom:12px}}
  .score-bar-wrap{{display:flex;align-items:center;gap:10px;margin-bottom:14px}}
  .score-bar-track{{flex:1;height:8px;background:#f1f5f9;border-radius:99px;overflow:hidden}}
  .score-bar-fill{{height:100%;border-radius:99px}}
  .score-num{{font-size:13px;font-weight:700;min-width:40px}}
  .phrase-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}}
  .phrase-col{{background:#f8fafc;border-radius:10px;padding:12px 14px}}
  .phrase-label{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#475569;margin-bottom:8px}}
  .tag{{display:inline-block;font-size:11px;border-radius:6px;padding:2px 8px;margin:2px 3px 2px 0;font-weight:500}}
  .tag-found{{background:#d1fae5;color:#065f46}}.tag-miss{{background:#fee2e2;color:#991b1b}}
  .evidence-box{{background:#fefce8;border:1px solid #fde68a;border-radius:8px;padding:10px 14px;font-size:12px;color:#713f12;margin-bottom:10px}}
  .why-box{{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:10px 14px;font-size:12px;color:#1e40af;margin-bottom:8px}}
  .fix-box{{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:10px 14px;font-size:12px;color:#14532d}}
  .method-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:16px}}
  .method-item{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px}}
  .method-num{{font-size:24px;font-weight:800;color:#3b82f6}}.method-desc{{font-size:12px;color:#475569;margin-top:4px}}
  .footer{{background:#0f172a;color:#94a3b8;text-align:center;padding:20px 48px;font-size:12px}}
  @media print{{body{{background:#fff}}.page{{box-shadow:none;margin:0;border-radius:0}}.no-print{{display:none!important}}.card{{break-inside:avoid}}}}
</style></head><body>
<div class="page">
  <div class="header">
    <div class="brand"><span style="font-size:28px">🛡️</span><div><div class="brand-name">AUDINEXIA</div><div class="brand-tag">GRC Compliance Platform</div></div></div>
    <div class="header-title">{framework_info['icon']} {framework_info['name']} Compliance Audit Report</div>
    <div class="header-sub">Automated policy analysis against regulatory controls</div>
    <div class="meta-chips"><span class="chip">📋 Report ID: {report_id}</span><span class="chip">📅 {timestamp.strftime('%d %B %Y, %H:%M')}</span><span class="chip">📄 {policy_name}</span></div>
  </div>
  <div class="score-band">
    <div>
      <svg viewBox="0 0 160 90" width="160" xmlns="http://www.w3.org/2000/svg">
        <path d="M15 80 A65 65 0 0 1 145 80" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round"/>
        <path d="M15 80 A65 65 0 0 1 145 80" fill="none" stroke="{score_color}" stroke-width="14" stroke-linecap="round" stroke-dasharray="204" stroke-dashoffset="{204 - (204 * overall_score / 100):.1f}"/>
        <text x="80" y="76" text-anchor="middle" font-family="Arial" font-size="24" font-weight="800" fill="{score_color}">{overall_score}%</text>
        <text x="80" y="88" text-anchor="middle" font-family="Arial" font-size="9" fill="#94a3b8">{score_label}</text>
      </svg>
    </div>
    <div class="stat-grid">
      <div class="stat-box"><div class="stat-num" style="color:#10b981">{compliant}</div><div class="stat-lbl">✅ Compliant</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#f59e0b">{partial}</div><div class="stat-lbl">⚠️ Partial</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#ef4444">{non_compliant}</div><div class="stat-lbl">❌ Non-Compliant</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#f97316">{high_risk}</div><div class="stat-lbl">🔴 High Risk</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#64748b">{len(results)}</div><div class="stat-lbl">📊 Controls</div></div>
    </div>
  </div>
  <div class="section"><div class="section-title">📊 Control Summary</div>
    <table class="summary-table"><thead><tr><th>ID</th><th>Control</th><th>Clause</th><th>Owner</th><th>Severity</th><th>Score</th><th>Status</th><th>Risk</th></tr></thead><tbody>{sum_rows}</tbody></table>
  </div>
  <div class="section"><div class="section-title">🔍 Detailed Control Analysis</div>{control_cards}</div>
  <div class="section" style="background:#f8fafc;border-top:1px solid #e2e8f0">
    <div class="section-title">📐 Scoring Methodology</div>
    <div class="method-grid">
      <div class="method-item"><div class="method-num">01</div><div class="method-desc"><strong>Phrase Matching</strong> - Required key phrases and synonyms detected across the policy text.</div></div>
      <div class="method-item"><div class="method-num">02</div><div class="method-desc"><strong>Raw Score</strong> - (Found phrases ÷ Total required) × 100 gives base coverage %.</div></div>
      <div class="method-item"><div class="method-num">03</div><div class="method-desc"><strong>Weighted Average</strong> - Critical controls (weight 10) carry more influence than major (7) or minor (5).</div></div>
      <div class="method-item"><div class="method-num">04</div><div class="method-desc"><strong>Thresholds</strong> - >=80% Compliant | 50-79% Partial | &lt;50% Non-Compliant.</div></div>
    </div>
  </div>
  <div class="footer"><strong>Audinexia GRC Engine v3.0</strong> &nbsp;|&nbsp; Auto-generated report - not legal advice &nbsp;|&nbsp; Report ID: {report_id}</div>
</div>
<div class="no-print" style="text-align:center;padding:20px 0 40px">
  <button onclick="window.print()" style="background:#0f172a;color:#fff;border:none;padding:12px 28px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer">🖨️ Print / Save as PDF</button>
</div>
</body></html>"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    return filepath


# ============================================================
# PROFESSIONAL PDF REPORT
# ============================================================

def generate_pdf_report(results, overall_score, policy_name, framework_info, report_id):
    import time as _time
    timestamp = datetime.now()
    _uid = str(int(_time.time() * 1000))[-6:]
    filename = (
        f"Audinexia_Report_{framework_info['name'].replace(' ', '_')}"
        f"_{timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    filepath = os.path.join(Config.REPORT_FOLDER, filename)

    DARK  = colors.HexColor('#0f172a')
    BLUE  = colors.HexColor('#2563eb')
    GREEN = colors.HexColor('#059669')
    AMBER = colors.HexColor('#d97706')
    RED   = colors.HexColor('#dc2626')
    LGRAY = colors.HexColor('#f1f5f9')
    MGRAY = colors.HexColor('#e2e8f0')
    SGRAY = colors.HexColor('#64748b')
    WHITE = colors.white

    score_color = GREEN if overall_score >= 80 else (AMBER if overall_score >= 50 else RED)
    score_label = "COMPLIANT" if overall_score >= 80 else ("PARTIAL" if overall_score >= 50 else "NON-COMPLIANT")

    doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=15*mm, bottomMargin=15*mm, leftMargin=18*mm, rightMargin=18*mm)
    W = A4[0] - 36*mm

    def S(name, **kw): return ParagraphStyle(f'{name}_{_uid}', **kw)
    sH2    = S('sH2',  fontName='Helvetica-Bold',   fontSize=13, textColor=DARK, spaceBefore=12, spaceAfter=6)
    sSmall = S('sSm',  fontName='Helvetica',         fontSize=7,  textColor=SGRAY, spaceAfter=2)
    sMono  = S('sMo',  fontName='Courier',           fontSize=7,  textColor=SGRAY)
    sCenter= S('sCtr', fontName='Helvetica',         fontSize=8,  textColor=DARK, alignment=TA_CENTER)
    sWhiteB= S('sWB',  fontName='Helvetica-Bold',    fontSize=9,  textColor=WHITE)
    sRt    = S('sRt',  fontName='Helvetica-Bold',    fontSize=8,  textColor=WHITE, alignment=TA_RIGHT)
    sEv    = S('sEv',  fontName='Helvetica-Oblique', fontSize=7.5, textColor=colors.HexColor('#713f12'), spaceAfter=2)
    sWhy   = S('sWhy', fontName='Helvetica',         fontSize=7.5, textColor=colors.HexColor('#1e40af'), spaceAfter=2)
    sFix   = S('sFix', fontName='Helvetica',         fontSize=7.5, textColor=colors.HexColor('#14532d'), spaceAfter=2)
    sGreen = S('sGr',  fontName='Helvetica-Bold',    fontSize=7.5, textColor=GREEN)
    sRed   = S('sRd',  fontName='Helvetica-Bold',    fontSize=7.5, textColor=RED)

    story = []

    def cpara(text, style, bg, pad=5):
        t = Table([[Paragraph(text, style)]], colWidths=[W])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),bg),('TOPPADDING',(0,0),(-1,-1),pad),('BOTTOMPADDING',(0,0),(-1,-1),pad),('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8)]))
        return t

    def hr(clr=MGRAY, t=0.5): return HRFlowable(width='100%', thickness=t, color=clr, spaceAfter=6, spaceBefore=4)

    compliant     = sum(1 for r in results if r['status'] == 'Compliant')
    partial       = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant = sum(1 for r in results if r['status'] == 'Non-Compliant')
    high_risk     = sum(1 for r in results if r['risk_level'] == 'High')

    cover = Table([[Paragraph(
        f'<font size="9" color="#38bdf8">AUDINEXIA  ·  GRC COMPLIANCE PLATFORM</font><br/>'
        f'<font size="20"><b>{framework_info["icon"]} {framework_info["name"]}</b></font><br/>'
        f'<font size="13">Compliance Audit Report</font>',
        S('cov', fontName='Helvetica-Bold', fontSize=20, textColor=WHITE, leading=28)
    )]], colWidths=[W])
    cover.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),DARK),('TOPPADDING',(0,0),(-1,-1),22),('BOTTOMPADDING',(0,0),(-1,-1),22),('LEFTPADDING',(0,0),(-1,-1),20),('RIGHTPADDING',(0,0),(-1,-1),20)]))
    story.append(cover)
    story.append(Spacer(1, 5*mm))

    meta_tbl = Table([[Paragraph(f'<b>Report ID:</b> {report_id}', sSmall), Paragraph(f'<b>Date:</b> {timestamp.strftime("%d %b %Y, %H:%M")}', sSmall), Paragraph(f'<b>Policy:</b> {policy_name}', sSmall)]], colWidths=[W/3]*3)
    meta_tbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LGRAY),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),('LEFTPADDING',(0,0),(-1,-1),8),('INNERGRID',(0,0),(-1,-1),0.3,MGRAY),('BOX',(0,0),(-1,-1),0.3,MGRAY)]))
    story.append(meta_tbl)
    story.append(Spacer(1, 6*mm))

    hero = Table([[
        Paragraph(f'<font size="38" color="{score_color.hexval()}"><b>{overall_score}%</b></font><br/><font size="9" color="{score_color.hexval()}"><b>{score_label}</b></font>', S('h', fontName='Helvetica-Bold', fontSize=38, alignment=TA_CENTER, leading=46)),
        Table([[Paragraph(f'<font size="22" color="#059669"><b>{compliant}</b></font>', sCenter), Paragraph('Compliant', sSmall)],
               [Paragraph(f'<font size="22" color="#d97706"><b>{partial}</b></font>', sCenter), Paragraph('Partial', sSmall)],
               [Paragraph(f'<font size="22" color="#dc2626"><b>{non_compliant}</b></font>', sCenter), Paragraph('Non-Compliant', sSmall)],
               [Paragraph(f'<font size="22" color="#f97316"><b>{high_risk}</b></font>', sCenter), Paragraph('High Risk', sSmall)],
               [Paragraph(f'<font size="22" color="#64748b"><b>{len(results)}</b></font>', sCenter), Paragraph('Controls', sSmall)]],
              colWidths=[18*mm, 52*mm])
    ]], colWidths=[48*mm, W-48*mm])
    hero.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LGRAY),('BOX',(0,0),(-1,-1),0.5,MGRAY),('TOPPADDING',(0,0),(-1,-1),12),('BOTTOMPADDING',(0,0),(-1,-1),12),('LEFTPADDING',(0,0),(-1,-1),10),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
    story.append(hero)
    story.append(Spacer(1, 7*mm))

    story.append(Paragraph('Control Summary', sH2))
    story.append(hr(BLUE, 1))
    rows = [['ID', 'Control', 'Clause', 'Owner', 'Sev.', 'Score', 'Status', 'Risk']]
    for c in results:
        sc = GREEN if c['status'] == 'Compliant' else (AMBER if c['status'] == 'Partially Compliant' else RED)
        rc = RED if c['risk_level'] == 'High' else (AMBER if c['risk_level'] == 'Medium' else GREEN)
        sid = re.sub(r'[^a-zA-Z0-9]', '_', c['id'])
        rows.append([
            Paragraph(f'<font size="6.5">{c["id"]}</font>', sMono),
            Paragraph(f'<b>{c["name"]}</b>', sSmall),
            Paragraph(c['clause'], sSmall),
            Paragraph(c['owner'], sSmall),
            Paragraph(c['severity'].capitalize(), sSmall),
            Paragraph(f'<b>{c["score"]}%</b>', S(f'sc_{sid}', fontName='Helvetica-Bold', fontSize=7, textColor=sc)),
            Paragraph(f'{c["status"]}', S(f'st_{sid}', fontName='Helvetica-Bold', fontSize=7, textColor=sc)),
            Paragraph(c['risk_level'], S(f'rk_{sid}', fontName='Helvetica-Bold', fontSize=7, textColor=rc)),
        ])

    col_w = [22*mm, 46*mm, 22*mm, 25*mm, 13*mm, 13*mm, 28*mm, 13*mm]
    st = Table(rows, colWidths=col_w, repeatRows=1)
    st.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),DARK),('TEXTCOLOR',(0,0),(-1,0),WHITE),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,0),7),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),('LEFTPADDING',(0,0),(-1,-1),5),('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE,LGRAY]),('GRID',(0,0),(-1,-1),0.3,MGRAY),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
    story.append(st)
    story.append(PageBreak())

    story.append(Paragraph('Detailed Control Analysis', sH2))
    story.append(hr(BLUE, 1))
    story.append(Spacer(1, 3*mm))

    for c in results:
        lc = RED if c['risk_level'] == 'High' else (AMBER if c['risk_level'] == 'Medium' else GREEN)
        sc = RED if c['status'] == 'Non-Compliant' else (AMBER if c['status'] == 'Partially Compliant' else GREEN)
        safe_id = re.sub(r'[^a-zA-Z0-9]', '_', c['id'])
        block = []
        # Header bar - use hyphen instead of middle-dot (ASCII safe)
        hdr = Table([[
            Paragraph(f'<font color="white"><b>{c["id"]}  -  {c["name"]}</b></font>', sWhiteB),
            Paragraph(f'<font color="white">{c["status"]}  |  {c["score"]}%</font>', sRt)
        ]], colWidths=[W*0.65, W*0.35])
        hdr.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),lc),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
        block.append(hdr)
        # Meta strip - use unique style name per control
        risk_style = S(f'rm_{safe_id}', fontName='Helvetica-Bold', fontSize=7,
                       textColor=(RED if c['risk_level']=='High' else (AMBER if c['risk_level']=='Medium' else GREEN)))
        meta = Table([[
            Paragraph(f'<b>Clause:</b> {c["clause"]}', sSmall),
            Paragraph(f'<b>Owner:</b> {c["owner"]}', sSmall),
            Paragraph(f'<b>Severity:</b> {c["severity"].capitalize()}', sSmall),
            Paragraph(f'<b>Weight:</b> {c["weight"]}', sSmall),
            Paragraph(f'<b>Risk:</b> {c["risk_level"]}', risk_style),
        ]], colWidths=[W/5]*5)
        meta.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LGRAY),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),('LEFTPADDING',(0,0),(-1,-1),6),('INNERGRID',(0,0),(-1,-1),0.3,MGRAY)]))
        block.append(meta)
        # ASCII progress bar (safe characters only)
        bar_pct = int(c['score'])
        filled  = int(bar_pct / 100 * 30)
        bar_str = '[' + '=' * filled + '-' * (30 - filled) + ']'
        bar_style = S(f'bar_{safe_id}', fontName='Courier', fontSize=7.5, spaceBefore=4, spaceAfter=4)
        block.append(Paragraph(
            f'<font color="{lc.hexval()}"><b>{bar_str}</b></font>  '
            f'<font size="9" color="{sc.hexval()}"><b>{c["score"]}%</b></font>',
            bar_style
        ))
        found_str   = ', '.join(c['found_phrases'])   or 'None detected'
        missing_str = ', '.join(c['missing_phrases']) or 'None - fully covered'
        fm = Table([[
            Table([[Paragraph('<b>Found Phrases</b>', sGreen)], [Paragraph(found_str, sSmall)]], colWidths=[(W/2)-3*mm]),
            Table([[Paragraph('<b>Missing Phrases</b>', sRed)],  [Paragraph(missing_str, sSmall)]], colWidths=[(W/2)-3*mm]),
        ]], colWidths=[W/2, W/2])
        fm.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),colors.HexColor('#f0fdf4')),('BACKGROUND',(1,0),(1,-1),colors.HexColor('#fef2f2')),('BOX',(0,0),(-1,-1),0.3,MGRAY),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),('LEFTPADDING',(0,0),(-1,-1),7)]))
        block.append(fm)
        # Evidence - strip separator lines, clean whitespace
        if c['evidence'] and len(c['evidence'].strip()) > 10:
            ev_clean = re.sub(r'\s+', ' ', c['evidence'][:240]).strip()
            if not ev_clean.endswith(('.', '!', '?')):
                ev_clean += '...'
            block.append(cpara(f'Evidence: {ev_clean}', sEv, colors.HexColor('#fefce8'), 6))
        block.append(cpara(f'Why it matters: {c["why_matters"]}', sWhy, colors.HexColor('#eff6ff'), 6))
        block.append(cpara(f'Recommended Fix: {c["fix_suggestion"]}', sFix, colors.HexColor('#f0fdf4'), 6))
        block.append(Spacer(1, 5*mm))
        story.append(KeepTogether(block))

    story.append(PageBreak())
    story.append(Paragraph('Scoring Methodology', sH2))
    story.append(hr(BLUE, 1))
    meth = Table([['Step', 'Description'],
                  ['01  Phrase Matching', 'Required key phrases and synonyms are detected across the policy text using context-aware matching.'],
                  ['02  Raw Score', '(Found phrases / Total required) x 100 gives base coverage % per control.'],
                  ['03  Weighted Score', 'Critical controls (weight 10) carry more influence than major (7) or minor (5). Final = weighted average.'],
                  ['04  Thresholds', '>=80% Compliant (Low Risk) | 50-79% Partial (Medium Risk) | <50% Non-Compliant (High Risk)']],
                 colWidths=[44*mm, W-44*mm], repeatRows=1)
    meth.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),DARK),('TEXTCOLOR',(0,0),(-1,0),WHITE),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),8),('FONTNAME',(0,1),(-1,-1),'Helvetica'),('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE,LGRAY]),('GRID',(0,0),(-1,-1),0.3,MGRAY),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('LEFTPADDING',(0,0),(-1,-1),8)]))
    story.append(meth)
    story.append(Spacer(1, 8*mm))
    disc_style = S('disc_rpt', fontName='Helvetica', fontSize=7, textColor=SGRAY)
    story.append(cpara(
        f'Disclaimer: This report is auto-generated by Audinexia GRC Engine v3.0 and is for informational purposes only. '
        f'It does not constitute legal advice. Report ID: {report_id}  |  Generated: {timestamp.strftime("%d %B %Y")}',
        disc_style, LGRAY, 8
    ))
    doc.build(story)
    return filepath


# ============================================================
# REVISED POLICY PDF — FINAL COMPLIANT POLICY ONLY
# Outputs the original policy text with all missing clauses
# fully merged in. No analysis, no gaps, no explanations.
# ============================================================

# Per-framework canonical section structure:
# Maps control_id -> (section_heading, clause_reference)
FRAMEWORK_SECTIONS = {
    'dpdpa': [
        ('DPDPA-1',  'CONSENT OBLIGATION',          'Section 6'),
        ('DPDPA-2',  'NOTICE TO DATA PRINCIPAL',    'Section 5'),
        ('DPDPA-3',  'PURPOSE LIMITATION',          'Section 6'),
        ('DPDPA-4',  'DATA MINIMIZATION',           'Section 6'),
        ('DPDPA-5',  'DATA RETENTION',              'Section 9'),
        ('DPDPA-6',  'DATA PRINCIPAL RIGHTS',       'Section 12'),
        ('DPDPA-7',  'GRIEVANCE REDRESSAL',         'Section 17'),
        ('DPDPA-8',  'DATA PROTECTION OFFICER',     'Section 9'),
        ('DPDPA-9',  'SECURITY SAFEGUARDS',         'Section 10'),
        ('DPDPA-10', 'BREACH NOTIFICATION',         'Section 11'),
        ('DPDPA-11', "CHILDREN'S DATA PROTECTION",  'Section 13'),
        ('DPDPA-12', 'CROSS-BORDER DATA TRANSFER',  'Section 17'),
    ],
    'iso27001': [
        ('A.5.1',  'INFORMATION SECURITY POLICY',   'Annex A.5.1'),
        ('A.5.2',  'POLICY REVIEW',                 'Annex A.5.2'),
        ('A.5.3',  'SEGREGATION OF DUTIES',         'Annex A.5.3'),
        ('A.7.2',  'SECURITY AWARENESS TRAINING',   'Annex A.7.2'),
        ('A.8.1',  'ASSET INVENTORY',               'Annex A.8.1'),
        ('A.9.1',  'ACCESS CONTROL POLICY',         'Annex A.9.1'),
        ('A.9.2',  'AUTHENTICATION',                'Annex A.9.2'),
        ('A.12.2', 'BACKUP AND RECOVERY',           'Annex A.12.2'),
        ('A.16.1', 'INCIDENT MANAGEMENT',           'Annex A.16.1'),
    ],
    'gdpr': [
        ('Art-5',  'PRINCIPLES OF PROCESSING',      'Article 5'),
        ('Art-6',  'LAWFUL BASIS FOR PROCESSING',   'Article 6'),
        ('Art-15', 'RIGHT TO ACCESS',               'Article 15'),
        ('Art-17', 'RIGHT TO ERASURE',              'Article 17'),
        ('Art-20', 'DATA PORTABILITY',              'Article 20'),
        ('Art-32', 'SECURITY OF PROCESSING',        'Article 32'),
        ('Art-33', 'BREACH NOTIFICATION',           'Article 33'),
        ('Art-37', 'DATA PROTECTION OFFICER',       'Article 37'),
    ],
    'pcidss': [
        ('Req-1',  'FIREWALL CONFIGURATION',                'Requirement 1'),
        ('Req-3',  'PROTECTION OF CARDHOLDER DATA',         'Requirement 3'),
        ('Req-6',  'SECURE DEVELOPMENT AND MAINTENANCE',    'Requirement 6'),
        ('Req-8',  'IDENTIFICATION AND AUTHENTICATION',     'Requirement 8'),
        ('Req-10', 'LOGGING AND MONITORING',                'Requirement 10'),
        ('Req-11', 'REGULAR SECURITY TESTING',              'Requirement 11'),
    ],
    'hipaa': [
        ('164.308(a)(1)', 'SECURITY MANAGEMENT PROCESS',    '45 CFR 164.308(a)(1)'),
        ('164.308(a)(5)', 'SECURITY AWARENESS TRAINING',    '45 CFR 164.308(a)(5)'),
        ('164.308(a)(6)', 'SECURITY INCIDENT PROCEDURES',   '45 CFR 164.308(a)(6)'),
        ('164.312(a)',    'ACCESS CONTROL',                  '45 CFR 164.312(a)'),
        ('164.312(b)',    'AUDIT CONTROLS',                  '45 CFR 164.312(b)'),
        ('164.312(e)',    'TRANSMISSION SECURITY',           '45 CFR 164.312(e)'),
    ],
    'nistcsf': [
        ('GV.OC-01', 'ORGANIZATIONAL CONTEXT',               'Govern (GV.OC)'),
        ('GV.RM-01', 'RISK MANAGEMENT STRATEGY',             'Govern (GV.RM)'),
        ('GV.SC-01', 'SUPPLY CHAIN RISK MANAGEMENT',         'Govern (GV.SC)'),
        ('ID.AM-01', 'ASSET MANAGEMENT',                     'Identify (ID.AM)'),
        ('ID.RA-01', 'RISK ASSESSMENT',                      'Identify (ID.RA)'),
        ('PR.AA-01', 'IDENTITY AND ACCESS MANAGEMENT',       'Protect (PR.AA)'),
        ('PR.DS-01', 'DATA SECURITY',                        'Protect (PR.DS)'),
        ('PR.PS-01', 'PLATFORM SECURITY',                    'Protect (PR.PS)'),
        ('PR.IR-01', 'TECHNOLOGY INFRASTRUCTURE RESILIENCE', 'Protect (PR.IR)'),
        ('DE.CM-01', 'CONTINUOUS MONITORING',                'Detect (DE.CM)'),
        ('DE.AE-01', 'ADVERSE EVENT ANALYSIS',               'Detect (DE.AE)'),
        ('RS.MA-01', 'INCIDENT MANAGEMENT',                  'Respond (RS.MA)'),
        ('RS.CO-01', 'INCIDENT COMMUNICATION',               'Respond (RS.CO)'),
        ('RC.RP-01', 'INCIDENT RECOVERY',                    'Recover (RC.RP)'),
    ],
}

# Full compliant policy body per framework (original + all required clauses merged in)
COMPLIANT_POLICY_BODY = {
    'dpdpa': [
        ('DPDPA-1', 'CONSENT OBLIGATION', 'Section 6', [
            "Valid, free, specific, informed, and unambiguous consent is obtained from Data Principals before processing personal data. Consent is collected via a clear double opt-in mechanism.",
            "A consent withdrawal mechanism is provided. Data Principals may withdraw consent at any time through account settings or by contacting the Data Protection Officer, without any detriment.",
            "Consent records, including timestamp, purpose, and method of consent, are maintained as part of the organisation's audit trail.",
            "Where processing relies on consent, a separate, granular consent is obtained for each distinct purpose.",
        ]),
        ('DPDPA-2', 'NOTICE TO DATA PRINCIPAL', 'Section 5', [
            "A clear and accessible privacy notice is provided to Data Principals before or at the time of collecting personal data.",
            "The notice includes: the purpose of processing, categories of personal data collected, retention period (data is retained for a maximum of 3 years after the last interaction, unless a longer period is required by law), rights of the Data Principal, and contact details of the Data Protection Officer.",
            "Notices are provided in plain language and are readily available on all digital touchpoints.",
        ]),
        ('DPDPA-3', 'PURPOSE LIMITATION', 'Section 6', [
            "Personal data is collected only for specified, explicit, and legitimate purposes that are documented prior to collection.",
            "Data is not processed for any purpose incompatible with the original specified purpose. No secondary use of personal data is permitted without obtaining fresh, explicit consent from the Data Principal.",
            "Purpose specification is documented and reviewed quarterly by the Privacy Officer.",
        ]),
        ('DPDPA-4', 'DATA MINIMIZATION', 'Section 6', [
            "Only data that is necessary, adequate, and relevant to the specified purpose is collected. Collection of excessive or irrelevant personal data is prohibited.",
            "Quarterly data minimization reviews are conducted to assess whether collected data remains necessary.",
            "Data minimization principles are embedded into product and system design (Privacy by Design).",
        ]),
        ('DPDPA-5', 'DATA RETENTION', 'Section 9', [
            "Personal data is retained only for the duration necessary to fulfil the specified purpose, or as required by applicable law.",
            "Data is retained for a maximum of 3 years after the last interaction with the Data Principal. Upon expiry of the retention period, data is securely and permanently deleted.",
            "Storage limitation controls are enforced through automated deletion schedules and quarterly retention audits.",
            "Data that is no longer required is erased without undue delay.",
        ]),
        ('DPDPA-6', 'DATA PRINCIPAL RIGHTS', 'Section 12', [
            "Data Principals have the right to access their personal data held by the organisation. Requests are acknowledged and fulfilled within 15 days.",
            "Data Principals have the right to correction of inaccurate or incomplete personal data.",
            "Data Principals have the right to erasure of their personal data where it is no longer necessary, or where consent is withdrawn.",
            "A grievance redressal mechanism is provided. Data Principals may submit grievances via the designated Grievance Officer contact channel.",
        ]),
        ('DPDPA-7', 'GRIEVANCE REDRESSAL', 'Section 17', [
            "A designated Grievance Officer is appointed. Contact details (name, email, phone) are published on the organisation's website and privacy notice.",
            "All grievances submitted by Data Principals are acknowledged within 48 hours and resolved within 15 days of receipt.",
            "A formal complaint process is documented and communicated to all Data Principals. Unresolved complaints may be escalated to the Data Protection Board of India.",
        ]),
        ('DPDPA-8', 'DATA PROTECTION OFFICER', 'Section 9', [
            "A Data Protection Officer (DPO) is appointed and their contact information is published and made available to Data Principals and the Data Protection Board.",
            "The DPO is responsible for: overseeing compliance with the DPDPA 2023, acting as the primary point of contact for regulatory inquiries, advising on data protection impact assessments, and monitoring data processing activities.",
            "The DPO operates independently and reports directly to senior management.",
        ]),
        ('DPDPA-9', 'SECURITY SAFEGUARDS', 'Section 10', [
            "Reasonable and appropriate security safeguards are implemented to prevent personal data breaches. These include:",
            "Encryption of personal data at rest using AES-256 and in transit using TLS 1.3 or higher.",
            "Role-based access control (RBAC) ensuring the principle of least privilege.",
            "Multi-factor authentication (MFA) is mandatory for all administrative and privileged system access.",
            "Regular security audits, vulnerability assessments, and penetration testing are conducted at least annually.",
            "Access controls and monitoring systems are reviewed quarterly.",
        ]),
        ('DPDPA-10', 'BREACH NOTIFICATION', 'Section 11', [
            "Data breach notification procedures are formally documented and tested.",
            "In the event of a personal data breach, the Data Protection Board of India is notified within 72 hours of becoming aware of the breach.",
            "Affected Data Principals are notified within 24 hours where the breach poses a high risk to their rights and freedoms.",
            "All breach incidents are logged, investigated, and documented, including the nature of the breach, categories and volumes of data affected, and remedial actions taken.",
        ]),
        ('DPDPA-11', "CHILDREN'S DATA PROTECTION", 'Section 13', [
            "Processing of personal data of children (individuals under 18 years of age) is prohibited without verifiable parental or guardian consent.",
            "Parental consent is obtained through a verified double opt-in mechanism, including OTP (One-Time Password) verification of the parent or guardian's contact details.",
            "An age verification gate is implemented at all digital entry points to identify and protect minors.",
            "Profiling, behavioural tracking, or targeted advertising directed at minors is strictly prohibited.",
        ]),
        ('DPDPA-12', 'CROSS-BORDER DATA TRANSFER', 'Section 17', [
            "Personal data is stored and processed within India by default (data localisation).",
            "Cross-border transfer of personal data is permitted only where: (a) the Data Principal has provided explicit consent, and (b) appropriate safeguards are in place, including Standard Contractual Clauses (SCCs), adequacy decisions, or binding corporate rules.",
            "All international data transfers are documented, reviewed by the DPO, and comply with applicable government notifications under the DPDPA 2023.",
        ]),
    ],
    'iso27001': [
        ('A.5.1', 'INFORMATION SECURITY POLICY', 'Annex A.5.1', [
            "The organisation has established a comprehensive Information Security Policy that is approved by executive management.",
            "The policy is documented, communicated to all employees and relevant third parties, and reviewed annually to ensure continued suitability, adequacy, and effectiveness.",
            "All employees are required to acknowledge and comply with the Information Security Policy.",
        ]),
        ('A.5.2', 'POLICY REVIEW', 'Annex A.5.2', [
            "The Information Security Policy is reviewed at planned intervals, at minimum annually, by management.",
            "Annual management review meetings are formally documented. Changes to the policy require documented management approval.",
            "All reviews, amendments, and approvals are recorded and retained as evidence of governance.",
        ]),
        ('A.5.3', 'SEGREGATION OF DUTIES', 'Annex A.5.3', [
            "Conflicting duties and areas of responsibility are segregated to reduce the risk of unauthorised or unintentional modification or misuse of assets.",
            "Separation of duties is enforced so that no single individual has end-to-end control over critical processes.",
            "Dual control is implemented for all critical and sensitive functions. Segregation requirements are reviewed annually.",
        ]),
        ('A.7.2', 'SECURITY AWARENESS TRAINING', 'Annex A.7.2', [
            "All employees receive information security awareness training upon hire and at least annually thereafter.",
            "Training includes phishing awareness, data protection, access control responsibilities, and incident reporting procedures.",
            "Security education is role-specific for staff handling sensitive data or with administrative access. Completion is tracked and documented.",
        ]),
        ('A.8.1', 'ASSET INVENTORY', 'Annex A.8.1', [
            "A complete and current inventory of all information assets is maintained and updated quarterly.",
            "The asset register includes: asset description, classification, ownership, location, and status.",
            "Each asset has an assigned owner responsible for its protection and compliance with applicable security controls.",
        ]),
        ('A.9.1', 'ACCESS CONTROL POLICY', 'Annex A.9.1', [
            "Access to information assets is governed by the principle of least privilege. Users are granted only the access necessary to perform their job function.",
            "Role-based access control (RBAC) is implemented. User access rights are reviewed and recertified quarterly.",
            "Access authorisation requires documented approval from the asset owner or line manager.",
        ]),
        ('A.9.2', 'AUTHENTICATION', 'Annex A.9.2', [
            "A strong password policy is enforced across all systems. Minimum password length is 12 characters with complexity requirements.",
            "Multi-factor authentication (MFA) is mandatory for all remote access, cloud systems, and administrative accounts.",
            "Passwords are changed at least every 90 days. Default and shared passwords are prohibited.",
        ]),
        ('A.12.2', 'BACKUP AND RECOVERY', 'Annex A.12.2', [
            "Regular backups of all critical data and systems are performed daily.",
            "Backups are stored offsite and/or in geographically separated secure cloud storage.",
            "Backup restoration is tested quarterly to verify recovery capability and integrity. Test results are documented.",
        ]),
        ('A.16.1', 'INCIDENT MANAGEMENT', 'Annex A.16.1', [
            "A documented and tested incident response plan is maintained. The plan is reviewed and updated at least annually.",
            "All security incidents, including actual or suspected data breaches, are reported immediately to the incident response team.",
            "Incidents are logged, investigated, and reported to management within 24 hours. Post-incident reviews are conducted to identify root causes and prevent recurrence.",
        ]),
    ],
    'gdpr': [
        ('Art-5', 'PRINCIPLES OF PROCESSING', 'Article 5', [
            "Personal data is processed lawfully, fairly, and in a transparent manner in relation to the data subject.",
            "Data is collected for specified, explicit, and legitimate purposes and is not further processed in a manner incompatible with those purposes (purpose limitation).",
            "Personal data is adequate, relevant, and limited to what is necessary in relation to the purposes for which it is processed (data minimisation).",
            "Data is kept accurate and up to date. Inaccurate data is erased or rectified without delay.",
            "Data is kept in a form which permits identification of data subjects for no longer than necessary (storage limitation).",
            "Processing is conducted with appropriate security, ensuring integrity and confidentiality.",
        ]),
        ('Art-6', 'LAWFUL BASIS FOR PROCESSING', 'Article 6', [
            "All processing of personal data is based on a documented lawful basis, including:",
            "Consent of the data subject, where freely given, specific, informed, and unambiguous.",
            "Performance of a contract to which the data subject is party.",
            "Compliance with a legal obligation to which the controller is subject.",
            "Legitimate interests pursued by the controller or a third party, where not overridden by the interests of the data subject.",
        ]),
        ('Art-15', 'RIGHT TO ACCESS', 'Article 15', [
            "Data subjects have the right to obtain confirmation of whether their personal data is being processed and to receive a copy of that data.",
            "Data subjects have the right to rectification of inaccurate personal data without undue delay.",
            "All access requests are acknowledged and fulfilled within one month of receipt. Extensions of up to two additional months may be applied for complex requests, with notification to the data subject.",
        ]),
        ('Art-17', 'RIGHT TO ERASURE', 'Article 17', [
            "Data subjects have the right to request erasure of their personal data without undue delay (Right to be Forgotten), where: data is no longer necessary, consent is withdrawn, or data has been unlawfully processed.",
            "Erasure requests are processed within 30 days. Where erasure is refused, the data subject is informed of the reasons and their right to lodge a complaint with the supervisory authority.",
        ]),
        ('Art-20', 'DATA PORTABILITY', 'Article 20', [
            "Data subjects have the right to receive their personal data in a structured, commonly used, and machine-readable format (e.g., CSV, JSON).",
            "Data subjects may request direct transfer of their data to another controller where technically feasible.",
            "Portability requests are fulfilled within one month of receipt.",
        ]),
        ('Art-32', 'SECURITY OF PROCESSING', 'Article 32', [
            "Appropriate technical and organisational measures are implemented to ensure a level of security appropriate to the risk, including:",
            "Encryption of personal data at rest (AES-256) and in transit (TLS 1.3).",
            "Pseudonymisation of personal data where applicable to reduce re-identification risk.",
            "Ongoing confidentiality, integrity, availability, and resilience of processing systems and services.",
            "Regular testing, assessment, and evaluation of the effectiveness of technical and organisational measures.",
        ]),
        ('Art-33', 'BREACH NOTIFICATION', 'Article 33', [
            "Personal data breaches are notified to the competent supervisory authority without undue delay and, where feasible, within 72 hours of becoming aware of the breach.",
            "Where notification is not made within 72 hours, the reasons for delay are provided.",
            "Where a breach is likely to result in a high risk to data subjects' rights and freedoms, affected data subjects are notified without undue delay.",
            "All breaches are documented, including facts, effects, and remedial actions taken.",
        ]),
        ('Art-37', 'DATA PROTECTION OFFICER', 'Article 37', [
            "A Data Protection Officer (DPO) is appointed in accordance with Article 37.",
            "The DPO's contact information is published and made available to data subjects and supervisory authorities.",
            "The DPO is responsible for monitoring compliance, advising on data protection obligations, and acting as the contact point for the supervisory authority.",
        ]),
    ],
    'pcidss': [
        ('Req-1', 'FIREWALL CONFIGURATION', 'Requirement 1', [
            "Firewall configuration standards are implemented and maintained across all network infrastructure.",
            "All firewalls are configured with a deny-all default rule. Inbound and outbound traffic is restricted to only necessary services and protocols.",
            "Network segmentation is enforced: the Cardholder Data Environment (CDE) is properly isolated from other networks and untrusted zones.",
            "Firewall rules are reviewed, validated, and approved by management at least every six months. Justification is documented for all permitted traffic.",
            "Default passwords on all network devices have been changed prior to deployment.",
        ]),
        ('Req-3', 'PROTECTION OF CARDHOLDER DATA', 'Requirement 3', [
            "Full magnetic stripe data, CVV2, and PIN data are never stored after authorisation.",
            "Primary Account Numbers (PAN) are stored with strong encryption (AES-256). PAN is masked when displayed, showing only the last four digits.",
            "Stored cardholder data is protected using tokenization or truncation where applicable.",
            "All stored cardholder data is encrypted at rest using AES-256. All cardholder data transmitted over public or open networks is encrypted using TLS 1.3.",
        ]),
        ('Req-6', 'SECURE DEVELOPMENT AND MAINTENANCE', 'Requirement 6', [
            "All applications are developed using secure coding guidelines, including the OWASP Top 10.",
            "Code reviews are performed by a second qualified developer before production deployment.",
            "Automated vulnerability scans are performed quarterly on all in-scope systems.",
            "Critical vulnerabilities are remediated within 15 days of identification. Patch management procedures ensure timely application of vendor-supplied security patches within 30 days of release.",
        ]),
        ('Req-8', 'IDENTIFICATION AND AUTHENTICATION', 'Requirement 8', [
            "Unique user IDs are assigned to every individual with system access. Shared or group accounts are prohibited for administrative access.",
            "Multi-factor authentication (MFA) is required for all remote network access and all access to the CDE, including administrative access.",
            "Minimum password length is 12 characters with complexity requirements (uppercase, lowercase, numeric, special character). Passwords expire every 90 days.",
            "Sessions automatically time out after 15 minutes of inactivity (session timeout).",
        ]),
        ('Req-10', 'LOGGING AND MONITORING', 'Requirement 10', [
            "All access to cardholder data, system components, and network resources is logged with a full audit trail.",
            "All authentication attempts, successful and failed, are logged and timestamped.",
            "Logs are retained for a minimum of 12 months, with at least 3 months immediately available for analysis.",
            "Logs are reviewed daily by the security team. Automated alerting is configured for anomalous activity.",
        ]),
        ('Req-11', 'REGULAR SECURITY TESTING', 'Requirement 11', [
            "Internal vulnerability scans are performed quarterly. External vulnerability scans are performed by a PCI SSC Approved Scanning Vendor (ASV) quarterly.",
            "Annual internal penetration tests and annual external penetration tests are conducted. All findings are risk-ranked and remediated before the next test cycle.",
            "Intrusion Detection and/or Prevention Systems (IDS/IPS) are deployed at all critical network entry and exit points. Signatures are updated continuously.",
        ]),
    ],
    'hipaa': [
        ('164.308(a)(1)', 'SECURITY MANAGEMENT PROCESS', '45 CFR 164.308(a)(1)', [
            "A formal risk analysis is conducted at least annually to identify threats and vulnerabilities to electronic protected health information (ePHI). Results are documented.",
            "Risk management policies are implemented to reduce identified risks to an acceptable level. Risk treatment decisions are documented and approved by management.",
            "A sanctions policy is established. Workforce members who fail to comply with security policies are subject to appropriate disciplinary action, up to and including termination.",
            "Information system activity is reviewed on a regular basis. Audit logs, access reports, and security incident tracking are reviewed at least weekly.",
        ]),
        ('164.308(a)(5)', 'SECURITY AWARENESS TRAINING', '45 CFR 164.308(a)(5)', [
            "All workforce members complete security awareness training upon hire and at least annually thereafter.",
            "Training includes: password management, malware protection, phishing awareness, and ePHI handling procedures.",
            "Periodic security reminders are issued to all staff, including updates on emerging threats and policy changes.",
            "Training completion is tracked and documented. Non-completion results in escalation under the sanctions policy.",
        ]),
        ('164.308(a)(6)', 'SECURITY INCIDENT PROCEDURES', '45 CFR 164.308(a)(6)', [
            "Security incident response procedures are documented and tested at least annually.",
            "All security incidents involving ePHI are identified, reported, and responded to immediately.",
            "Response and reporting procedures include: incident identification, containment, eradication, recovery, and post-incident review.",
            "In the event of a breach of unsecured ePHI, the Department of Health and Human Services (HHS) is notified within 60 days of discovery. Affected individuals are notified without unreasonable delay.",
        ]),
        ('164.312(a)', 'ACCESS CONTROL', '45 CFR 164.312(a)', [
            "Unique user identification is required for all users accessing ePHI. Shared accounts are prohibited.",
            "Emergency access procedures are documented for obtaining necessary ePHI during an emergency or system outage.",
            "Automatic logoff is enforced after a defined period of inactivity on all systems containing ePHI.",
            "All ePHI stored on end-user devices and portable media is encrypted using AES-256.",
        ]),
        ('164.312(b)', 'AUDIT CONTROLS', '45 CFR 164.312(b)', [
            "Audit logs record all access to ePHI, including user identification, date, time, and action taken.",
            "Audit logs are reviewed at least weekly for suspicious or anomalous activity.",
            "Activity review procedures are documented and include escalation paths for identified anomalies.",
            "Audit records are retained for a minimum of 6 years. Recording access and all access events are captured in the audit trail.",
        ]),
        ('164.312(e)', 'TRANSMISSION SECURITY', '45 CFR 164.312(e)', [
            "All ePHI transmitted over open or public networks is encrypted using TLS 1.2 or higher (TLS 1.3 preferred).",
            "Integrity controls are implemented to ensure that ePHI is not improperly modified during transmission.",
            "Secure transmission policies are documented and enforced for all electronic communication channels used to transmit ePHI.",
        ]),
    ],
    'nistcsf': [
        ('GV.OC-01', 'ORGANIZATIONAL CONTEXT', 'Govern (GV.OC)', [
            "The organization has documented its mission, vision, and strategic cybersecurity objectives, aligning cybersecurity risk management to business priorities.",
            "Internal and external stakeholders, including leadership, employees, regulators, customers, and third-party partners, are identified and their cybersecurity expectations are documented.",
            "Cybersecurity governance structures, roles, and responsibilities are formally defined. Risk tolerance levels are established, communicated, and reviewed at least annually.",
            "The legal, regulatory, and contractual cybersecurity obligations applicable to the organization are identified and integrated into governance processes.",
        ]),
        ('GV.RM-01', 'RISK MANAGEMENT STRATEGY', 'Govern (GV.RM)', [
            "A formal cybersecurity risk management strategy is documented and approved by senior leadership.",
            "Risk appetite and risk tolerance levels are defined, quantified where possible, and embedded into all cybersecurity decision-making processes.",
            "Cybersecurity risk management is fully integrated into enterprise risk management (ERM) and operational planning. Priorities for risk treatment are documented and reviewed quarterly.",
            "Risk management policies, procedures, and accountability structures are established, communicated, and enforced across the organization.",
        ]),
        ('GV.SC-01', 'SUPPLY CHAIN RISK MANAGEMENT', 'Govern (GV.SC)', [
            "A supply chain risk management policy is documented, identifying critical suppliers, third-party service providers, and technology vendors.",
            "Cybersecurity requirements are included in all supplier contracts and vendor agreements. Due diligence assessments are conducted prior to onboarding third parties.",
            "Third-party vendor risk assessments are conducted at least annually, or upon significant changes in the relationship. High-risk vendors are subject to enhanced scrutiny.",
            "Processes exist to monitor ongoing supplier compliance with cybersecurity requirements and to respond to supply chain incidents.",
        ]),
        ('ID.AM-01', 'ASSET MANAGEMENT', 'Identify (ID.AM)', [
            "A comprehensive and current asset inventory is maintained covering all hardware, software, data assets, cloud services, and network infrastructure.",
            "Assets are classified by type, criticality, sensitivity, and ownership. The asset register is reviewed and updated at least quarterly.",
            "Data assets, including their location, classification, and data flows, are documented. All assets are assigned a named owner responsible for their protection.",
        ]),
        ('ID.RA-01', 'RISK ASSESSMENT', 'Identify (ID.RA)', [
            "Formal risk assessments are conducted at least annually and upon significant changes to the environment, systems, or threat landscape.",
            "The risk assessment process includes: threat identification, vulnerability identification, analysis of likelihood and potential impact, and prioritization of risks for treatment.",
            "Risk assessment results are documented and used to inform the risk management strategy, security controls, and investment priorities.",
            "Threat intelligence from internal and external sources is incorporated into risk assessments to reflect the current threat environment.",
        ]),
        ('PR.AA-01', 'IDENTITY AND ACCESS MANAGEMENT', 'Protect (PR.AA)', [
            "Identity management policies and procedures are formally documented. All users, devices, and services are assigned unique identifiers.",
            "Access control policies enforce the principle of least privilege. Access rights are reviewed and recertified at least quarterly.",
            "Authentication requirements are enforced: multi-factor authentication (MFA) is mandatory for all privileged accounts, remote access, and cloud services.",
            "Authorization policies ensure that access to sensitive systems and data is granted only on a need-to-know and need-to-use basis. Unused accounts are disabled promptly.",
        ]),
        ('PR.DS-01', 'DATA SECURITY', 'Protect (PR.DS)', [
            "Data protection policies govern the classification, handling, storage, and disposal of all organizational data.",
            "Encryption is applied to data at rest (AES-256) and data in transit (TLS 1.3). Key management procedures are documented and enforced.",
            "Data integrity controls are implemented to detect unauthorized modification of data. Hash verification and checksums are used for critical data assets.",
            "Data loss prevention (DLP) controls are deployed to prevent unauthorized exfiltration of sensitive data.",
        ]),
        ('PR.PS-01', 'PLATFORM SECURITY', 'Protect (PR.PS)', [
            "Secure configuration baselines and hardening standards are defined and applied to all systems, platforms, and network devices.",
            "Configuration management processes ensure that systems are deployed and maintained in accordance with approved baselines. Deviations are detected and remediated.",
            "A patch management policy ensures that security patches are applied within defined timeframes. Critical patches are applied within 15 days of release. Vulnerability management reviews are conducted monthly.",
            "Software is tested for security vulnerabilities prior to deployment. Unauthorized software installation is prohibited.",
        ]),
        ('PR.IR-01', 'TECHNOLOGY INFRASTRUCTURE RESILIENCE', 'Protect (PR.IR)', [
            "Resilience requirements, including Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO), are defined for all critical systems.",
            "Backup procedures are implemented for all critical data and systems. Backups are stored securely, including at least one offsite or cloud copy.",
            "Business continuity and disaster recovery plans are documented, tested at least annually, and updated to reflect changes in the environment.",
            "Availability controls, including redundancy and failover mechanisms, are implemented to ensure the ongoing operation of critical cybersecurity functions.",
        ]),
        ('DE.CM-01', 'CONTINUOUS MONITORING', 'Detect (DE.CM)', [
            "Continuous security monitoring is implemented across networks, systems, endpoints, cloud services, and user activity.",
            "Security information and event management (SIEM) or equivalent log monitoring tools are deployed. Logs are retained for a minimum of 12 months.",
            "Automated anomaly detection capabilities are configured to alert on indicators of compromise, policy violations, and unusual activity patterns.",
            "Network monitoring covers all ingress and egress points, including monitoring for unauthorized connections, data exfiltration, and lateral movement.",
        ]),
        ('DE.AE-01', 'ADVERSE EVENT ANALYSIS', 'Detect (DE.AE)', [
            "Processes are defined for collecting, correlating, and analyzing security events from multiple sources to identify adverse events and incidents.",
            "Thresholds and criteria for incident detection, escalation, and declaration are formally documented. Security events are triaged and classified by severity.",
            "Event analysis incorporates threat intelligence to distinguish true positives from false positives and to contextualize security events.",
            "All detected anomalies and security events are logged, investigated, and documented regardless of whether they result in a declared incident.",
        ]),
        ('RS.MA-01', 'INCIDENT MANAGEMENT', 'Respond (RS.MA)', [
            "A documented incident response plan defines roles, responsibilities, and procedures for identifying, containing, eradicating, and recovering from cybersecurity incidents.",
            "The incident response plan is tested at least annually through tabletop exercises or simulations. Lessons learned are incorporated into plan updates.",
            "Incident containment procedures limit the spread and impact of cybersecurity incidents. Eradication procedures remove threat actors, malware, and malicious artifacts.",
            "All incidents are formally logged, investigated, and classified. Post-incident reviews identify root causes and improvement actions.",
        ]),
        ('RS.CO-01', 'INCIDENT COMMUNICATION', 'Respond (RS.CO)', [
            "Incident communication procedures define how information about cybersecurity incidents is shared internally with leadership, affected teams, and the board.",
            "External notification and reporting procedures comply with regulatory, contractual, and legal obligations. Regulatory disclosure timelines are documented and followed.",
            "Stakeholder communication templates and protocols are pre-defined to enable rapid, accurate, and consistent communication during incidents.",
            "Procedures for public disclosure of cybersecurity incidents are documented, reviewed by legal counsel, and approved by senior leadership.",
        ]),
        ('RC.RP-01', 'INCIDENT RECOVERY', 'Recover (RC.RP)', [
            "Recovery plans are documented for all critical systems and services, with defined Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO).",
            "Restoration procedures are tested at least annually to validate their effectiveness and to identify gaps in recovery capability.",
            "Resilience improvements identified through incident recovery and post-incident reviews are tracked, prioritized, and implemented.",
            "Lessons learned from all cybersecurity incidents are formally documented and used to improve detection, response, and recovery capabilities on a continuous basis.",
        ]),
    ],
}


def generate_revised_policy_pdf(policy_text, missing_sections, framework_name, policy_filename, framework_info):
    """
    Generate a final, fully compliant policy PDF.
    Outputs only the complete revised policy — no analysis, no gap cards, no explanations.
    All missing clauses from the Detailed Control Analysis are fully merged in.
    """
    import time
    timestamp = datetime.now()
    _uid = str(int(time.time() * 1000))[-6:]
    filename = f"Revised_Policy_{framework_name.replace(' ', '_')}_{timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(Config.REPORT_FOLDER, filename)

    # ── Colours ───────────────────────────────────────────────────
    DARK   = colors.HexColor('#0f172a')
    NAVY   = colors.HexColor('#1e3a5f')
    BLUE   = colors.HexColor('#1d4ed8')
    GREEN  = colors.HexColor('#059669')
    LGRAY  = colors.HexColor('#f8fafc')
    MGRAY  = colors.HexColor('#e2e8f0')
    SGRAY  = colors.HexColor('#64748b')
    WHITE  = colors.white
    ACCENT = colors.HexColor(framework_info.get('color', '#1d4ed8'))

    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        topMargin=22*mm, bottomMargin=20*mm,
        leftMargin=22*mm, rightMargin=22*mm
    )
    W = A4[0] - 44*mm

    # ── Styles (all unique per call) ──────────────────────────────
    def S(name, **kw): return ParagraphStyle(f'{name}_{_uid}', **kw)

    sCover    = S('cov',  fontName='Helvetica-Bold',   fontSize=24, textColor=WHITE,  leading=32, alignment=TA_CENTER)
    sDocInfo  = S('di',   fontName='Helvetica',        fontSize=9,  textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER, spaceAfter=2)
    sMeta     = S('mt',   fontName='Helvetica',        fontSize=8,  textColor=SGRAY,  spaceAfter=2)
    sSecHdr   = S('sh',   fontName='Helvetica-Bold',   fontSize=10, textColor=WHITE)
    sBody     = S('bo',   fontName='Helvetica',        fontSize=9,  textColor=DARK,   spaceAfter=5, leading=14)
    sBodyBold = S('bbo',  fontName='Helvetica-Bold',   fontSize=9,  textColor=DARK,   spaceAfter=3, leading=14)
    sBullet   = S('bu',   fontName='Helvetica',        fontSize=9,  textColor=DARK,   spaceAfter=4, leading=13,
                  leftIndent=12, firstLineIndent=-12)
    sFooter   = S('ft',   fontName='Helvetica',        fontSize=7,  textColor=SGRAY,  alignment=TA_CENTER, leading=10)
    sAmended  = S('am',   fontName='Helvetica-Oblique',fontSize=8,  textColor=colors.HexColor('#0f766e'),
                  spaceAfter=4, leading=12, leftIndent=8)

    story = []

    def hr(clr=MGRAY, t=0.5, b=6):
        return HRFlowable(width='100%', thickness=t, color=clr, spaceAfter=b, spaceBefore=2)

    def section_header_block(ctrl_id, section_title, clause_ref):
        """Dark branded section header for each policy section."""
        hdr = Table([[
            Paragraph(f'<b>{section_title}</b>', sSecHdr),
            Paragraph(f'<font color="#94a3b8">{clause_ref}</font>', S(f'cr_{ctrl_id}_{_uid}', fontName='Helvetica', fontSize=8, textColor=colors.HexColor('#94a3b8'), alignment=TA_RIGHT)),
        ]], colWidths=[W * 0.72, W * 0.28])
        hdr.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), DARK),
            ('TOPPADDING',    (0,0), (-1,-1), 9),
            ('BOTTOMPADDING', (0,0), (-1,-1), 9),
            ('LEFTPADDING',   (0,0), (-1,-1), 12),
            ('RIGHTPADDING',  (0,0), (-1,-1), 12),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        return hdr

    # ── COVER PAGE ────────────────────────────────────────────────
    cover = Table([[Paragraph(
        f'<font size="9" color="#64748b">AUDINEXIA GRC ENGINE v3.0</font><br/><br/>'
        f'<font size="24"><b>FULLY REVISED COMPLIANCE POLICY</b></font><br/><br/>'
        f'<font size="13">{framework_name}</font>',
        sCover
    )]], colWidths=[W])
    cover.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), DARK),
        ('TOPPADDING',    (0,0), (-1,-1), 36),
        ('BOTTOMPADDING', (0,0), (-1,-1), 36),
        ('LEFTPADDING',   (0,0), (-1,-1), 20),
        ('RIGHTPADDING',  (0,0), (-1,-1), 20),
    ]))
    story.append(cover)
    story.append(Spacer(1, 5*mm))

    # Accent bar under cover
    accent_bar = Table([['']], colWidths=[W])
    accent_bar.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), ACCENT),
        ('TOPPADDING',    (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ]))
    story.append(accent_bar)
    story.append(Spacer(1, 5*mm))

    # Document metadata strip
    meta = Table([[
        Paragraph(f'<b>Original File:</b> {policy_filename}',           sMeta),
        Paragraph(f'<b>Generated:</b> {timestamp.strftime("%d %B %Y")}', sMeta),
        Paragraph(f'<b>Version:</b> Revised v2.0 (100% Compliant)',      sMeta),
    ]], colWidths=[W/3]*3)
    meta.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,-1), LGRAY),
        ('BOX',         (0,0), (-1,-1), 0.4, MGRAY),
        ('INNERGRID',   (0,0), (-1,-1), 0.4, MGRAY),
        ('TOPPADDING',  (0,0), (-1,-1), 7),
        ('BOTTOMPADDING',(0,0),(-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(meta)
    story.append(Spacer(1, 4*mm))

    # Compliance statement banner
    banner = Table([[Paragraph(
        'This document is the fully revised and compliant version of the submitted policy. '
        'All gaps identified during the compliance audit have been resolved. '
        'This policy meets 100% of the required controls for ' + framework_name + '.',
        S('bn', fontName='Helvetica', fontSize=8.5, textColor=colors.HexColor('#14532d'),
          alignment=TA_CENTER, leading=13)
    )]], colWidths=[W])
    banner.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor('#d1fae5')),
        ('BOX',           (0,0), (-1,-1), 0.8, GREEN),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING',   (0,0), (-1,-1), 14),
        ('RIGHTPADDING',  (0,0), (-1,-1), 14),
    ]))
    story.append(banner)
    story.append(Spacer(1, 6*mm))

    # Table of Contents placeholder line
    story.append(Paragraph(
        f'<b>EFFECTIVE DATE:</b> {timestamp.strftime("%d %B %Y")}  |  '
        f'<b>DOCUMENT ID:</b> {framework_info.get("name","").upper()[:3]}-POL-REVISED-001  |  '
        f'<b>STATUS:</b> Active',
        S('toc', fontName='Helvetica', fontSize=8, textColor=SGRAY, alignment=TA_CENTER)
    ))
    story.append(Spacer(1, 4*mm))
    story.append(hr(ACCENT, 1.5, 8))

    # ── POLICY SECTIONS ───────────────────────────────────────────
    # Determine which framework key to use
    fw_key = next((k for k, v in FRAMEWORKS.items() if v['name'] == framework_name), None)

    # Get the full compliant body for this framework
    policy_body = COMPLIANT_POLICY_BODY.get(fw_key, [])

    # Build a set of control IDs that had missing phrases (for amendment markers)
    amended_ids = {ms['control_id'] for ms in missing_sections}

    for idx, entry in enumerate(policy_body, 1):
        ctrl_id, section_title, clause_ref, clauses = entry

        # Section header
        story.append(section_header_block(ctrl_id, f'{idx}. {section_title}', clause_ref))

        # Was this section amended?
        was_amended = ctrl_id in amended_ids
        if was_amended:
            story.append(Paragraph(
                '[Amended: This section has been updated to address identified compliance gaps.]',
                sAmended
            ))

        # Policy clauses
        for clause in clauses:
            # Detect bullet-style lines (start with a keyword continuation)
            if clause.startswith(('Encryption', 'Role-based', 'Multi-factor', 'Regular',
                                  'Consent of', 'Performance', 'Compliance with', 'Legitimate',
                                  'Data subjects', 'Data Principals', 'Unique user',
                                  'Internal vulnerability', 'Annual internal')):
                story.append(Paragraph(f'- {clause}', sBullet))
            else:
                story.append(Paragraph(clause, sBody))

        story.append(Spacer(1, 4*mm))

        # Thin divider between sections (not after last)
        if idx < len(policy_body):
            story.append(hr(MGRAY, 0.4, 4))

    # ── FOOTER DISCLAIMER ─────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(hr(ACCENT, 1, 6))
    disc = Table([[Paragraph(
        f'This policy document has been automatically revised by Audinexia GRC Engine v3.0 to achieve full compliance '
        f'with {framework_name}. This output does not constitute legal advice. '
        f'All additions should be reviewed and validated by qualified legal counsel and your Data Protection Officer '
        f'before publication. Generated: {timestamp.strftime("%d %B %Y, %H:%M")}.',
        sFooter
    )]], colWidths=[W])
    disc.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), LGRAY),
        ('BOX',           (0,0), (-1,-1), 0.3, MGRAY),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('RIGHTPADDING',  (0,0), (-1,-1), 10),
    ]))
    story.append(disc)

    doc.build(story)
    return filepath
