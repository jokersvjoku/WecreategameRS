"""Report generation service — PDF and JSON."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    Flowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.schemas import PatchResult, ScanResult, Severity

# Colour palette per severity
_SEVERITY_COLORS: Dict[str, colors.Color] = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#6B7280"),
}


class _HorizontalLine(Flowable):
    """Draw a thin horizontal rule."""

    def __init__(self, width: float, color: colors.Color = colors.grey) -> None:
        super().__init__()
        self._width = width
        self._color = color

    def draw(self) -> None:
        self.canv.setStrokeColor(self._color)
        self.canv.setLineWidth(0.5)
        self.canv.line(0, 0, self._width, 0)

    def wrap(self, avail_width: float, avail_height: float):  # type: ignore[override]
        return self._width, 2 * mm


class ReportService:
    """Generate PDF and JSON security reports."""

    # ------------------------------------------------------------------
    # PDF
    # ------------------------------------------------------------------

    def generate_pdf_report(
        self,
        scan_result: ScanResult,
        patch_result: Optional[PatchResult] = None,
    ) -> bytes:
        """Build a professional PDF security report and return the raw bytes."""
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story: List[Flowable] = []

        # ---- custom styles ----
        title_style = ParagraphStyle(
            "PPTitle",
            parent=styles["Title"],
            fontSize=28,
            leading=34,
            textColor=colors.HexColor("#1E293B"),
            alignment=TA_CENTER,
            spaceAfter=6 * mm,
        )
        subtitle_style = ParagraphStyle(
            "PPSubtitle",
            parent=styles["Normal"],
            fontSize=12,
            textColor=colors.HexColor("#64748B"),
            alignment=TA_CENTER,
            spaceAfter=12 * mm,
        )
        heading_style = ParagraphStyle(
            "PPHeading",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=8 * mm,
            spaceAfter=4 * mm,
        )
        body_style = ParagraphStyle(
            "PPBody",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "PPCode",
            parent=styles["Code"],
            fontSize=8,
            leading=10,
            backColor=colors.HexColor("#F1F5F9"),
            borderColor=colors.HexColor("#CBD5E1"),
            borderWidth=0.5,
            borderPadding=4,
            fontName="Courier",
            textColor=colors.HexColor("#1E293B"),
        )
        meta_style = ParagraphStyle(
            "PPMeta",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#94A3B8"),
            alignment=TA_RIGHT,
        )

        # ---- Title page ----
        story.append(Spacer(1, 4 * cm))
        story.append(Paragraph("PATCHPILOT", title_style))
        story.append(Paragraph("Security Scan Report", subtitle_style))
        story.append(_HorizontalLine(doc.width))
        story.append(Spacer(1, 8 * mm))

        scanned_at = scan_result.scanned_at
        if isinstance(scanned_at, str):
            scanned_at_str = scanned_at
        else:
            scanned_at_str = scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        meta_lines = [
            f"<b>Scan ID:</b> {scan_result.scan_id}",
            f"<b>File:</b> {scan_result.filename or 'N/A'}",
            f"<b>Language:</b> {scan_result.language}",
            f"<b>Scanned at:</b> {scanned_at_str}",
            f"<b>Scan time:</b> {scan_result.scan_time:.4f}s",
        ]
        for ml in meta_lines:
            story.append(Paragraph(ml, body_style))
        story.append(Spacer(1, 10 * mm))

        # ---- Summary table ----
        story.append(Paragraph("Vulnerability Summary", heading_style))

        summary = scan_result.summary
        table_data = [
            ["Severity", "Count"],
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            count = summary.get(sev, 0)
            table_data.append([sev.upper(), str(count)])
        table_data.append(["TOTAL", str(summary.get("total", len(scan_result.vulnerabilities)))])

        summary_table = Table(table_data, colWidths=[6 * cm, 4 * cm])
        ts = TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#F8FAFC")]),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#F1F5F9")),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ]
        )
        # Color-code severity cells
        for i, sev in enumerate(("critical", "high", "medium", "low", "info"), start=1):
            c = _SEVERITY_COLORS.get(sev, colors.black)
            ts.add("TEXTCOLOR", (0, i), (0, i), c)

        summary_table.setStyle(ts)
        story.append(summary_table)
        story.append(Spacer(1, 8 * mm))

        # ---- Detailed findings ----
        if scan_result.vulnerabilities:
            story.append(Paragraph("Detailed Findings", heading_style))
            story.append(_HorizontalLine(doc.width))
            story.append(Spacer(1, 4 * mm))

            for i, vuln in enumerate(scan_result.vulnerabilities, start=1):
                sev_color = _SEVERITY_COLORS.get(vuln.severity.value, colors.black)
                sev_hex = sev_color.hexval() if hasattr(sev_color, "hexval") else "#000000"

                header = (
                    f'<b>#{i}</b> &nbsp; '
                    f'<font color="{sev_hex}">[{vuln.severity.value.upper()}]</font> &nbsp; '
                    f"<b>{_escape(vuln.title)}</b>"
                )
                story.append(Paragraph(header, body_style))

                details = [
                    f"<b>Rule:</b> {vuln.rule_id}",
                ]
                if vuln.cwe_id:
                    details.append(f"<b>CWE:</b> {vuln.cwe_id}")
                if vuln.line_number:
                    details.append(f"<b>Line:</b> {vuln.line_number}")
                details.append(f"<b>Description:</b> {_escape(vuln.description)}")

                for d in details:
                    story.append(Paragraph(d, body_style))

                if vuln.snippet:
                    story.append(Spacer(1, 2 * mm))
                    story.append(Paragraph(_escape(vuln.snippet), code_style))

                story.append(Spacer(1, 4 * mm))
                story.append(_HorizontalLine(doc.width, colors.HexColor("#E2E8F0")))
                story.append(Spacer(1, 4 * mm))

        # ---- Patch details ----
        if patch_result:
            story.append(Paragraph("Patch Details", heading_style))
            story.append(_HorizontalLine(doc.width))
            story.append(Spacer(1, 4 * mm))

            if patch_result.patches_applied:
                for p in patch_result.patches_applied:
                    line_info = f" (line {p.get('line_number', '?')})" if p.get("line_number") else ""
                    story.append(
                        Paragraph(
                            f"<b>{p.get('rule_id', 'N/A')}</b>{line_info}: "
                            f"{_escape(str(p.get('description', '')))}",
                            body_style,
                        )
                    )
                    story.append(Spacer(1, 2 * mm))

            if patch_result.ai_explanation:
                story.append(Spacer(1, 4 * mm))
                story.append(Paragraph("<b>Explanation:</b>", body_style))
                story.append(
                    Paragraph(_escape(patch_result.ai_explanation), body_style)
                )

        # ---- Footer ----
        story.append(Spacer(1, 1 * cm))
        story.append(_HorizontalLine(doc.width))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(
            Paragraph(f"Report generated by PATCHPILOT on {now}", meta_style)
        )

        doc.build(story)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def generate_json_report(
        self,
        scan_result: ScanResult,
        patch_result: Optional[PatchResult] = None,
    ) -> Dict[str, Any]:
        """Return a structured JSON-serializable report."""
        report: Dict[str, Any] = {
            "report_type": "patchpilot_security_report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "scan_id": scan_result.scan_id,
                "filename": scan_result.filename,
                "language": scan_result.language,
                "scan_time": scan_result.scan_time,
                "scanned_at": (
                    scan_result.scanned_at.isoformat()
                    if isinstance(scan_result.scanned_at, datetime)
                    else str(scan_result.scanned_at)
                ),
                "summary": scan_result.summary,
                "vulnerabilities": [
                    {
                        "rule_id": v.rule_id,
                        "severity": v.severity.value,
                        "title": v.title,
                        "description": v.description,
                        "line_number": v.line_number,
                        "column": v.column,
                        "snippet": v.snippet,
                        "cwe_id": v.cwe_id,
                    }
                    for v in scan_result.vulnerabilities
                ],
            },
        }
        if patch_result:
            report["patches"] = {
                "scan_id": patch_result.scan_id,
                "patches_applied": patch_result.patches_applied,
                "ai_explanation": patch_result.ai_explanation,
                "original_code": patch_result.original_code,
                "patched_code": patch_result.patched_code,
            }
        return report


def _escape(text: str) -> str:
    """Escape XML entities for ReportLab Paragraph markup."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
