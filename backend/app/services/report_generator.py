from datetime import datetime
from typing import List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from app.models import Vulnerability, Patch


# Brand colours
CYBER_DARK = colors.HexColor("#0f172a")
CYBER_CYAN = colors.HexColor("#06b6d4")
CYBER_EMERALD = colors.HexColor("#10b981")
CYBER_RED = colors.HexColor("#ef4444")
CYBER_ORANGE = colors.HexColor("#f97316")
CYBER_YELLOW = colors.HexColor("#eab308")
CYBER_BLUE = colors.HexColor("#3b82f6")
CYBER_GRAY = colors.HexColor("#6b7280")
WHITE = colors.white
LIGHT_GRAY = colors.HexColor("#f3f4f6")
MID_GRAY = colors.HexColor("#e5e7eb")

SEVERITY_COLORS = {
    "critical": CYBER_RED,
    "high": CYBER_ORANGE,
    "medium": CYBER_YELLOW,
    "low": CYBER_BLUE,
    "info": CYBER_GRAY,
}


class ReportGenerator:
    """Generates professional PDF security reports with ReportLab."""

    def generate_pdf(
        self,
        scan_id: str,
        original_code: str,
        patched_code: Optional[str],
        vulnerabilities: List[Vulnerability],
        patches: List[Patch],
    ) -> bytes:
        from io import BytesIO
        buf = BytesIO()

        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        story = []

        # ----------------------------------------------------------------
        # Title Page
        # ----------------------------------------------------------------
        title_style = ParagraphStyle(
            "PatchPilotTitle",
            parent=styles["Title"],
            fontSize=28,
            textColor=CYBER_CYAN,
            spaceAfter=6,
            alignment=TA_CENTER,
        )
        subtitle_style = ParagraphStyle(
            "PatchPilotSubtitle",
            parent=styles["Normal"],
            fontSize=12,
            textColor=CYBER_GRAY,
            alignment=TA_CENTER,
            spaceAfter=4,
        )
        story.append(Spacer(1, 1.5 * cm))
        story.append(Paragraph("PATCHPILOT", title_style))
        story.append(Paragraph("Security Scan Report", subtitle_style))
        story.append(Paragraph("Find the flaw. Fix the code. Prove the patch.", subtitle_style))
        story.append(Spacer(1, 0.5 * cm))
        story.append(HRFlowable(width="100%", thickness=2, color=CYBER_CYAN))
        story.append(Spacer(1, 0.4 * cm))

        meta_style = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9, textColor=CYBER_GRAY)
        story.append(Paragraph(f"Scan ID: {scan_id}", meta_style))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
        story.append(Spacer(1, 1 * cm))

        # ----------------------------------------------------------------
        # Executive Summary
        # ----------------------------------------------------------------
        h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=14,
                             textColor=CYBER_CYAN, spaceAfter=8, spaceBefore=12)
        story.append(Paragraph("Executive Summary", h1))

        total = len(vulnerabilities)
        critical = sum(1 for v in vulnerabilities if v.severity == "critical")
        high = sum(1 for v in vulnerabilities if v.severity == "high")
        medium = sum(1 for v in vulnerabilities if v.severity == "medium")
        low = sum(1 for v in vulnerabilities if v.severity == "low")
        info = sum(1 for v in vulnerabilities if v.severity == "info")
        patched_count = len(patches)

        summary_data = [
            ["Metric", "Count"],
            ["Total Vulnerabilities", str(total)],
            ["Critical", str(critical)],
            ["High", str(high)],
            ["Medium", str(medium)],
            ["Low", str(low)],
            ["Info", str(info)],
            ["Patches Generated", str(patched_count)],
        ]

        summary_table = Table(summary_data, colWidths=[9 * cm, 4 * cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), CYBER_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), CYBER_CYAN),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, WHITE]),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.8 * cm))

        # ----------------------------------------------------------------
        # Vulnerability Details
        # ----------------------------------------------------------------
        if vulnerabilities:
            story.append(Paragraph("Vulnerability Details", h1))
            h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11,
                                 textColor=CYBER_DARK, spaceAfter=4, spaceBefore=10)
            body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9,
                                  textColor=CYBER_DARK, spaceAfter=3)
            code_style = ParagraphStyle("Code", parent=styles["Code"], fontSize=8,
                                         textColor=CYBER_DARK, backColor=LIGHT_GRAY,
                                         leftIndent=10, spaceAfter=4)

            for i, vuln in enumerate(vulnerabilities, 1):
                sev_color = SEVERITY_COLORS.get(vuln.severity, CYBER_GRAY)
                vuln_block = []

                vuln_block.append(Paragraph(
                    f"{i}. [{vuln.severity.upper()}] {vuln.title}",
                    ParagraphStyle("VH", parent=h2, textColor=sev_color),
                ))
                vuln_block.append(Paragraph(
                    f"<b>Rule:</b> {vuln.rule_id} | <b>CWE:</b> {vuln.cwe_id or 'N/A'} | "
                    f"<b>File:</b> {vuln.file} | <b>Lines:</b> {vuln.line_start}–{vuln.line_end}",
                    body,
                ))
                vuln_block.append(Paragraph(f"<b>Description:</b> {vuln.description}", body))
                vuln_block.append(Paragraph(f"<b>Recommendation:</b> {vuln.recommendation}", body))

                if vuln.code_snippet:
                    snippet_safe = vuln.code_snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    vuln_block.append(Paragraph(f"<b>Code Snippet:</b>", body))
                    for line in snippet_safe.splitlines()[:10]:
                        vuln_block.append(Paragraph(line or " ", code_style))

                story.append(KeepTogether(vuln_block))
                story.append(Spacer(1, 0.4 * cm))

        # ----------------------------------------------------------------
        # Patches Applied
        # ----------------------------------------------------------------
        if patches:
            story.append(Paragraph("Security Patches", h1))
            body = ParagraphStyle("Body2", parent=styles["Normal"], fontSize=9,
                                  textColor=CYBER_DARK, spaceAfter=3)
            code_style2 = ParagraphStyle("Code2", parent=styles["Code"], fontSize=8,
                                          textColor=CYBER_DARK, backColor=LIGHT_GRAY,
                                          leftIndent=10, spaceAfter=4)

            for i, patch in enumerate(patches, 1):
                conf_pct = int(patch.confidence * 100)
                patch_block = []
                patch_block.append(Paragraph(
                    f"Patch {i} — Confidence: {conf_pct}%",
                    ParagraphStyle("PH", parent=styles["Heading2"], fontSize=11,
                                   textColor=CYBER_EMERALD, spaceAfter=4, spaceBefore=10),
                ))
                patch_block.append(Paragraph(f"<b>Explanation:</b> {patch.explanation}", body))

                if patch.original_code != patch.patched_code:
                    patch_block.append(Paragraph("<b>Original (vulnerable):</b>", body))
                    for line in (patch.original_code or "")[:500].splitlines()[:8]:
                        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        patch_block.append(Paragraph(safe or " ", code_style2))

                    patch_block.append(Paragraph("<b>Patched (secure):</b>", body))
                    for line in (patch.patched_code or "")[:500].splitlines()[:8]:
                        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        patch_block.append(Paragraph(safe or " ", code_style2))

                story.append(KeepTogether(patch_block))
                story.append(Spacer(1, 0.4 * cm))

        # ----------------------------------------------------------------
        # Footer note
        # ----------------------------------------------------------------
        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=CYBER_GRAY))
        story.append(Spacer(1, 0.2 * cm))
        footer_style = ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8,
                                       textColor=CYBER_GRAY, alignment=TA_CENTER)
        story.append(Paragraph(
            "Generated by PATCHPILOT · Powered by Google Gemma 4 · DigitalOcean Gradient",
            footer_style,
        ))

        doc.build(story)
        return buf.getvalue()
