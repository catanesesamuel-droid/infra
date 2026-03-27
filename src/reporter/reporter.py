"""
IEC 62443-3-3 Compliance Analyzer
Módulo: reporter.py
Descripción: Genera un informe PDF profesional a partir del análisis
             producido por analyzer.py.

Requiere: reportlab
  pip install reportlab --break-system-packages
"""

import json
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF


# ─────────────────────────────────────────────
# Paleta de colores
# ─────────────────────────────────────────────

C_NAVY      = colors.HexColor("#0D2137")
C_BLUE      = colors.HexColor("#185FA5")
C_BLUE_SOFT = colors.HexColor("#E6F1FB")
C_TEAL      = colors.HexColor("#0F6E56")
C_TEAL_SOFT = colors.HexColor("#E1F5EE")
C_RED       = colors.HexColor("#A32D2D")
C_RED_SOFT  = colors.HexColor("#FCEBEB")
C_AMBER     = colors.HexColor("#854F0B")
C_AMBER_SOFT= colors.HexColor("#FAEEDA")
C_GRAY      = colors.HexColor("#444441")
C_GRAY_SOFT = colors.HexColor("#F1EFE8")
C_WHITE     = colors.white
C_BLACK     = colors.HexColor("#1A1A18")

SL_COLORS = {
    0: colors.HexColor("#E24B4A"),
    1: colors.HexColor("#EF9F27"),
    2: colors.HexColor("#1D9E75"),
    3: colors.HexColor("#185FA5"),
    4: colors.HexColor("#3C3489"),
}

STATUS_COLORS = {
    "pass":    colors.HexColor("#1D9E75"),
    "fail":    colors.HexColor("#E24B4A"),
    "warning": colors.HexColor("#EF9F27"),
    "unknown": colors.HexColor("#888780"),
}

STATUS_ICON = {
    "pass":    "✓",
    "fail":    "✗",
    "warning": "⚠",
    "unknown": "?",
}


# ─────────────────────────────────────────────
# Estilos tipográficos
# ─────────────────name─────────────────────────
# ─────────────────────────────────────────────

def build_styles():
    base = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle(
            "cover_title", fontSize=28, textColor=C_WHITE,
            fontName="Helvetica-Bold", leading=34, alignment=TA_CENTER,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", fontSize=13, textColor=colors.HexColor("#B5D4F4"),
            fontName="Helvetica", leading=18, alignment=TA_CENTER,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", fontSize=10, textColor=colors.HexColor("#D3D1C7"),
            fontName="Helvetica", leading=14, alignment=TA_CENTER,
        ),
        "section_h1": ParagraphStyle(
            "section_h1", fontSize=16, textColor=C_NAVY,
            fontName="Helvetica-Bold", leading=20, spaceBefore=14, spaceAfter=4,
        ),
        "section_h2": ParagraphStyle(
            "section_h2", fontSize=12, textColor=C_BLUE,
            fontName="Helvetica-Bold", leading=16, spaceBefore=10, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", fontSize=9, textColor=C_BLACK,
            fontName="Helvetica", leading=13, spaceAfter=4,
        ),
        "body_small": ParagraphStyle(
            "body_small", fontSize=8, textColor=C_GRAY,
            fontName="Helvetica", leading=11,
        ),
        "mono": ParagraphStyle(
            "mono", fontSize=8, textColor=C_NAVY,
            fontName="Courier", leading=11, leftIndent=6,
            backColor=C_GRAY_SOFT, borderPad=3,
        ),
        "tag_pass": ParagraphStyle(
            "tag_pass", fontSize=8, textColor=C_TEAL,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "tag_fail": ParagraphStyle(
            "tag_fail", fontSize=8, textColor=C_RED,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "tag_warning": ParagraphStyle(
            "tag_warning", fontSize=8, textColor=C_AMBER,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "footer", fontSize=7, textColor=colors.HexColor("#888780"),
            fontName="Helvetica", alignment=TA_CENTER,
        ),
    }
    return styles


# ─────────────────────────────────────────────
# Gráficos
# ─────────────────────────────────────────────

def make_sl_badge(sl: int, size: float = 40) -> Drawing:
    """Dibuja un badge circular con el Security Level."""
    d = Drawing(size, size)
    color = SL_COLORS.get(sl, C_GRAY)
    d.add(Circle(size / 2, size / 2, size / 2 - 2, fillColor=color, strokeColor=C_WHITE, strokeWidth=1.5))
    label = f"SL{sl}"
    d.add(String(size / 2, size / 2 - 4, label,
                 fontSize=11, fillColor=C_WHITE,
                 fontName="Helvetica-Bold", textAnchor="middle"))
    return d


def make_compliance_bar(percent: float, width: float = 120, height: float = 12) -> Drawing:
    """Barra de progreso de cumplimiento."""
    d = Drawing(width, height)
    # Fondo gris
    d.add(Rect(0, 0, width, height, fillColor=C_GRAY_SOFT, strokeColor=None, rx=4, ry=4))
    # Barra coloreada
    filled = max(4, (percent / 100) * width)
    bar_color = (
        SL_COLORS[2] if percent >= 70 else
        SL_COLORS[1] if percent >= 40 else
        SL_COLORS[0]
    )
    d.add(Rect(0, 0, filled, height, fillColor=bar_color, strokeColor=None, rx=4, ry=4))
    # Texto
    d.add(String(width / 2, 2, f"{percent:.0f}%",
                 fontSize=7, fillColor=C_WHITE if percent >= 20 else C_BLACK,
                 fontName="Helvetica-Bold", textAnchor="middle"))
    return d


def make_pie_chart(passed: int, failed: int, warnings: int) -> Drawing:
    """Gráfico de tarta para resumen de checks."""
    d = Drawing(120, 90)
    pie = Pie()
    pie.x = 10
    pie.y = 5
    pie.width = 80
    pie.height = 80
    total = passed + failed + warnings or 1
    pie.data = [passed, failed, warnings]
    pie.labels = None
    pie.slices[0].fillColor = SL_COLORS[2]
    pie.slices[1].fillColor = SL_COLORS[0]
    pie.slices[2].fillColor = SL_COLORS[1]
    pie.slices.strokeColor = C_WHITE
    pie.slices.strokeWidth = 1
    d.add(pie)
    # Leyenda lateral
    items = [
        (SL_COLORS[2], f"Pass  {passed}"),
        (SL_COLORS[0], f"Fail  {failed}"),
        (SL_COLORS[1], f"Warn  {warnings}"),
    ]
    for i, (color, label) in enumerate(items):
        y = 68 - i * 16
        d.add(Rect(94, y, 8, 8, fillColor=color, strokeColor=None))
        d.add(String(106, y + 1, label, fontSize=7, fillColor=C_BLACK, fontName="Helvetica"))
    return d


# ─────────────────────────────────────────────
# Secciones del informe
# ─────────────────────────────────────────────

def cover_page(report: dict, styles: dict) -> list:
    """Portada del informe."""
    story = []

    # Bloque de cabecera azul oscuro simulado con tabla
    cover_data = [[
        Paragraph("IEC 62443-3-3", styles["cover_title"]),
    ], [
        Paragraph("Informe de Cumplimiento de Seguridad", styles["cover_sub"]),
    ], [
        Spacer(1, 8),
    ], [
        Paragraph(
            f"Sistema: <b>{report['os_name']} {report['os_version']}</b> — "
            f"Host: <b>{report['hostname']}</b>",
            styles["cover_meta"]
        ),
    ], [
        Paragraph(
            f"Generado: {report['collection_timestamp'][:19].replace('T', ' ')} UTC",
            styles["cover_meta"]
        ),
    ]]

    cover_table = Table(cover_data, colWidths=[150 * mm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 20))

    # Resumen ejecutivo rápido
    overall_sl = report.get("overall_sl", 0)
    compliance  = report.get("overall_compliance_percent", 0)
    total       = report.get("total_checks", 0)
    passed      = report.get("passed_checks", 0)
    failed      = report.get("failed_checks", 0)
    warnings    = report.get("warning_checks", 0)
    sl_labels   = {
        0: "Sin protección",
        1: "SL1 — Accidental",
        2: "SL2 — Intencional simple",
        3: "SL3 — Sofisticado",
        4: "SL4 — Avanzado",
    }

    summary_data = [
        ["Security Level global", "Cumplimiento", "Checks totales", "Fallidos"],
        [
            Paragraph(f"<b>SL{overall_sl}</b><br/>{sl_labels.get(overall_sl, '')}", styles["body"]),
            Paragraph(f"<b>{compliance}%</b>", styles["body"]),
            Paragraph(f"<b>{total}</b>", styles["body"]),
            Paragraph(f"<b>{failed}</b>", styles["body"]),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[38 * mm] * 4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BLUE_SOFT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BLUE),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # Mini gráfico de checks
    pie = make_pie_chart(passed, failed, warnings)
    story.append(pie)
    story.append(Spacer(1, 6))

    story.append(PageBreak())
    return story


def fr_section(fr: dict, styles: dict) -> list:
    """Genera la sección de un Foundational Requirement."""
    story = []

    sl = fr.get("sl_achieved", 0)
    compliance = fr.get("compliance_percent", 0.0)
    checks = fr.get("checks", [])

    # Cabecera del FR
    header_data = [[
        Paragraph(f"<b>{fr['fr_id']}</b> — {fr['title']}", styles["section_h1"]),
        make_sl_badge(sl, size=36),
    ]]
    header_table = Table(header_data, colWidths=[130 * mm, 20 * mm])
    header_table.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",    (0, 0), (-1, -1), C_BLUE_SOFT),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(KeepTogether([header_table]))
    story.append(Spacer(1, 4))

    # Barra de cumplimiento
    bar_data = [[
        Paragraph("Cumplimiento:", styles["body_small"]),
        make_compliance_bar(compliance, width=110, height=11),
    ]]
    bar_table = Table(bar_data, colWidths=[28 * mm, 122 * mm])
    bar_table.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(bar_table)
    story.append(Spacer(1, 8))

    # Tabla de checks
    table_header = [
        Paragraph("<b>SR</b>", styles["body_small"]),
        Paragraph("<b>Control</b>", styles["body_small"]),
        Paragraph("<b>SL</b>", styles["body_small"]),
        Paragraph("<b>Estado</b>", styles["body_small"]),
    ]
    rows = [table_header]

    for check in checks:
        status = check.get("status", "unknown")
        icon = STATUS_ICON.get(status, "?")
        style_key = f"tag_{status}" if status in ("pass", "fail", "warning") else "body_small"

        status_para = Paragraph(
            f"<b>{icon} {status.upper()}</b>",
            styles.get(style_key, styles["body_small"])
        )

        rows.append([
            Paragraph(check.get("sr_id", ""), styles["body_small"]),
            Paragraph(check.get("title", ""), styles["body"]),
            Paragraph(str(check.get("sl_contribution", "")), styles["body_small"]),
            status_para,
        ])

        # Si falla o warning, añadir detalle y remediación
        if status in ("fail", "warning"):
            detail = check.get("detail", "")
            remediation = check.get("remediation", "")
            rem_lines = remediation.strip().splitlines()

            detail_para = Paragraph(f"<i>{detail}</i>", styles["body_small"])

            # Primera línea de remediación como texto
            rem_text = rem_lines[0] if rem_lines else ""
            rem_para = Paragraph(f"<b>Rem:</b> {rem_text}", styles["body_small"])

            # Si hay comandos (líneas siguientes), mostrarlos en mono
            cmd_lines = [l for l in rem_lines[1:] if l.strip()]
            if cmd_lines:
                cmd_text = "  ".join(cmd_lines[:2])
                cmd_para = Paragraph(cmd_text, styles["mono"])
                detail_cell = [detail_para, rem_para, cmd_para]
            else:
                detail_cell = [detail_para, rem_para]

            rows.append([
                Paragraph("", styles["body_small"]),
                detail_cell,
                Paragraph("", styles["body_small"]),
                Paragraph("", styles["body_small"]),
            ])

    col_widths = [18 * mm, 104 * mm, 10 * mm, 18 * mm]
    check_table = Table(rows, colWidths=col_widths, repeatRows=1)

    row_colors = []
    for i in range(1, len(rows)):
        bg = C_WHITE if i % 2 == 0 else C_GRAY_SOFT
        row_colors.append(("BACKGROUND", (0, i), (-1, i), bg))

    check_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#D3D1C7")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        *row_colors,
    ]))
    story.append(check_table)
    story.append(Spacer(1, 14))

    return story


def summary_table_section(report: dict, styles: dict) -> list:
    """Tabla resumen de todos los FR."""
    story = []
    story.append(Paragraph("Resumen por Foundational Requirement", styles["section_h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=8))

    header = [
        Paragraph("<b>FR</b>", styles["body_small"]),
        Paragraph("<b>Nombre</b>", styles["body_small"]),
        Paragraph("<b>SL alcanzado</b>", styles["body_small"]),
        Paragraph("<b>Cumplimiento</b>", styles["body_small"]),
        Paragraph("<b>Pass</b>", styles["body_small"]),
        Paragraph("<b>Fail</b>", styles["body_small"]),
    ]
    rows = [header]

    sl_labels = {0: "SL0", 1: "SL1", 2: "SL2", 3: "SL3", 4: "SL4"}

    for fr in report.get("fr_results", []):
        sl = fr.get("sl_achieved", 0)
        checks = fr.get("checks", [])
        p = sum(1 for c in checks if c.get("status") == "pass")
        f = sum(1 for c in checks if c.get("status") == "fail")
        sl_color = SL_COLORS.get(sl, C_GRAY)

        rows.append([
            Paragraph(f"<b>{fr['fr_id']}</b>", styles["body"]),
            Paragraph(fr.get("title", ""), styles["body"]),
            Paragraph(f"<b>{sl_labels[sl]}</b>", styles["body"]),
            make_compliance_bar(fr.get("compliance_percent", 0), width=60, height=10),
            Paragraph(f"<b>{p}</b>", styles["tag_pass"]),
            Paragraph(f"<b>{f}</b>", styles["tag_fail"]),
        ])

    col_widths = [12 * mm, 62 * mm, 22 * mm, 26 * mm, 14 * mm, 14 * mm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)

    row_bgs = [("BACKGROUND", (0, i), (-1, i),
                C_GRAY_SOFT if i % 2 == 1 else C_WHITE)
               for i in range(1, len(rows))]
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (2, 0), (2, -1), "CENTER"),
        ("ALIGN",         (4, 0), (-1, -1), "CENTER"),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#D3D1C7")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        *row_bgs,
    ]))
    story.append(t)
    story.append(Spacer(1, 16))
    return story


def remediation_section(report: dict, styles: dict) -> list:
    """Lista priorizada de acciones correctivas."""
    story = []
    story.append(PageBreak())
    story.append(Paragraph("Plan de remediación", styles["section_h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_RED, spaceAfter=8))
    story.append(Paragraph(
        "Acciones ordenadas por prioridad: primero los controles de SL1 fallidos "
        "(base mínima de seguridad), luego SL2 y SL3.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    # Recoger todos los checks fallidos
    failed_checks = []
    for fr in report.get("fr_results", []):
        for check in fr.get("checks", []):
            if check.get("status") in ("fail", "warning"):
                failed_checks.append({**check, "fr_id": fr["fr_id"]})

    # Ordenar: primero fail > warning, luego por sl_contribution ascendente
    failed_checks.sort(key=lambda c: (
        0 if c["status"] == "fail" else 1,
        c.get("sl_contribution", 4)
    ))

    for i, check in enumerate(failed_checks, 1):
        sl = check.get("sl_contribution", 0)
        status = check.get("status", "fail")
        icon = "✗" if status == "fail" else "⚠"
        style_icon = styles["tag_fail"] if status == "fail" else styles["tag_warning"]

        header_data = [[
            Paragraph(f"<b>{icon}</b>", style_icon),
            Paragraph(
                f"<b>{check['fr_id']} / {check['sr_id']}</b> — {check['title']}",
                styles["section_h2"]
            ),
            Paragraph(f"SL{sl}", styles["body_small"]),
        ]]
        ht = Table(header_data, colWidths=[8 * mm, 128 * mm, 14 * mm])
        ht.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(ht)

        story.append(Paragraph(
            f"<b>Hallazgo:</b> {check.get('detail', '')}",
            styles["body_small"]
        ))

        rem_lines = check.get("remediation", "").strip().splitlines()
        if rem_lines:
            story.append(Paragraph(f"<b>Acción:</b> {rem_lines[0]}", styles["body_small"]))
            cmd_lines = [l.strip() for l in rem_lines[1:] if l.strip()]
            for cmd in cmd_lines[:3]:
                story.append(Paragraph(cmd, styles["mono"]))

        story.append(HRFlowable(
            width="100%", thickness=0.3,
            color=colors.HexColor("#D3D1C7"), spaceAfter=4
        ))

    return story


# ─────────────────────────────────────────────
# Cabecera y pie de página
# ─────────────────────────────────────────────

def make_page_template(canvas_obj, doc):
    """Dibuja cabecera y pie en cada página (excepto portada)."""
    canvas_obj.saveState()
    w, h = A4

    if doc.page > 1:
        # Línea superior
        canvas_obj.setStrokeColor(C_NAVY)
        canvas_obj.setLineWidth(1.5)
        canvas_obj.line(15 * mm, h - 12 * mm, w - 15 * mm, h - 12 * mm)

        # Título en cabecera
        canvas_obj.setFont("Helvetica-Bold", 8)
        canvas_obj.setFillColor(C_NAVY)
        canvas_obj.drawString(15 * mm, h - 10 * mm, "IEC 62443-3-3 — Informe de Cumplimiento")
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(C_GRAY)
        canvas_obj.drawRightString(w - 15 * mm, h - 10 * mm,
                                   f"Página {doc.page}")

        # Pie de página
        canvas_obj.setStrokeColor(colors.HexColor("#D3D1C7"))
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(15 * mm, 12 * mm, w - 15 * mm, 12 * mm)
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(colors.HexColor("#888780"))
        canvas_obj.drawCentredString(
            w / 2, 8 * mm,
            "Generado por IEC 62443-3-3 Compliance Analyzer — Documento confidencial"
        )

    canvas_obj.restoreState()


# ─────────────────────────────────────────────
# Generador principal del PDF
# ─────────────────────────────────────────────

def generate_pdf(report: dict, output_path: str = "compliance_report.pdf") -> str:
    """
    Genera el PDF completo de cumplimiento IEC 62443-3-3.

    Args:
        report: dict con el output de analyzer.analyze()
        output_path: ruta del PDF de salida

    Returns:
        Ruta absoluta del PDF generado
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="IEC 62443-3-3 Compliance Report",
        author="IEC 62443-3-3 Analyzer",
        subject=f"{report.get('os_name', '')} {report.get('os_version', '')} — {report.get('hostname', '')}",
    )

    styles = build_styles()
    story = []

    # 1. Portada
    story += cover_page(report, styles)

    # 2. Tabla resumen
    story += summary_table_section(report, styles)

    # 3. Detalle por FR
    story.append(Paragraph("Análisis detallado por FR", styles["section_h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=8))

    for fr in report.get("fr_results", []):
        story += fr_section(fr, styles)

    # 4. Plan de remediación
    story += remediation_section(report, styles)

    doc.build(story, onFirstPage=make_page_template, onLaterPages=make_page_template)

    return str(Path(output_path).resolve())


# ─────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="IEC 62443-3-3 Reporter — Genera informe PDF desde el análisis"
    )
    parser.add_argument("--input",  "-i", default="analysis_report.json",
                        help="JSON de entrada (output del analyzer)")
    parser.add_argument("--output", "-o", default="compliance_report.pdf",
                        help="Archivo PDF de salida")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Archivo no encontrado: {input_path}")
        print("    Ejecuta primero: python3 analyzer.py --input collection_output.json --output analysis_report.json")
        exit(1)

    report = json.loads(input_path.read_text(encoding="utf-8"))
    out = generate_pdf(report, args.output)
    print(f"[+] Informe PDF generado: {out}")
