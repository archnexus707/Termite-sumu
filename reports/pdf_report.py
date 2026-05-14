import datetime
import os
from typing import List

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER

from core.base_connector import LogEntry
from config.settings import EXPORTS_DIR, SENSITIVE_FILE_PERMS, APP_NAME, APP_VERSION


def export_logs_pdf(entries: List[LogEntry], host: str) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"device_logs_{host}_{ts}.pdf"
    path = os.path.join(EXPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Normal"],
                                 fontSize=18, textColor=colors.HexColor("#1f6feb"),
                                 spaceAfter=6, alignment=TA_CENTER, fontName="Helvetica-Bold")
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"],
                                fontSize=9, textColor=colors.HexColor("#8b949e"),
                                spaceAfter=4, alignment=TA_CENTER)
    section_style = ParagraphStyle("Section", parent=styles["Normal"],
                                   fontSize=11, textColor=colors.HexColor("#58a6ff"),
                                   spaceBefore=12, spaceAfter=6, fontName="Helvetica-Bold")
    body_style = ParagraphStyle("Body", parent=styles["Normal"],
                                fontSize=8, fontName="Courier",
                                textColor=colors.HexColor("#e6edf3"),
                                backColor=colors.HexColor("#0d1117"),
                                spaceAfter=2)

    story = []
    story.append(Paragraph(f"{APP_NAME} — Log Report", title_style))
    story.append(Paragraph(f"Host: {host} | Generated: {datetime.datetime.utcnow().isoformat()}Z | Version: {APP_VERSION}", meta_style))
    story.append(Paragraph("CONFIDENTIAL — Authorized Use Only", meta_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363d")))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Log Entries", section_style))

    LEVEL_COLORS = {
        "Critical": colors.HexColor("#da3633"),
        "Error": colors.HexColor("#f85149"),
        "Warning": colors.HexColor("#d29922"),
        "Information": colors.HexColor("#58a6ff"),
        "INFO": colors.HexColor("#58a6ff"),
        "WARN": colors.HexColor("#d29922"),
        "ERROR": colors.HexColor("#f85149"),
    }

    table_data = [["Timestamp", "Source", "Level", "Message"]]
    for entry in entries[:10000]:
        table_data.append([
            str(entry.timestamp)[:22],
            str(entry.source)[:30],
            str(entry.level)[:12],
            str(entry.message)[:120],
        ])

    col_widths = [3.5*cm, 4*cm, 2*cm, 9.5*cm]
    tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#8b949e")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("FONTNAME", (0, 1), (-1, -1), "Courier"),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#e6edf3")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#30363d")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(tbl)

    doc.build(story)
    os.chmod(path, SENSITIVE_FILE_PERMS)
    return path
