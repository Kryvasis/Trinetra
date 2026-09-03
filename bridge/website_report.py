"""Printable report from the exact signed website observation, without re-scanning."""
from io import BytesIO
from xml.sax.saxutils import escape


def build_pdf(report):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak

    buffer = BytesIO()
    styles = getSampleStyleSheet()
    for name in ("Heading1", "Heading2", "Heading3"):
        styles[name].keepWithNext = True
    styles.add(ParagraphStyle(name="CortexBody", fontName="Helvetica", fontSize=10, leading=15, spaceAfter=9, splitLongWords=True))
    styles.add(ParagraphStyle(name="CortexMeta", parent=styles["CortexBody"], fontSize=8, leading=12, textColor=colors.HexColor("#454955")))
    styles.add(ParagraphStyle(name="CortexOutcome", parent=styles["CortexMeta"], keepWithNext=True))
    story = []
    def p(text, style="CortexBody"):
        # All target-provided text is escaped; never interpreted as report markup.
        story.append(Paragraph(escape(str(text)), styles[style]))
    def field(label, value):
        p(label, "Heading3")
        p(value)
    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#454955"))
        canvas.drawString(42, 26, "CORTEX | Website observation | Not a compliance certification")
        canvas.drawRightString(A4[0] - 42, 26, str(doc.page))

    p("CORTEX", "Heading1")
    p("Website observation report", "Title")
    p("Public response evidence, review guidance and assessment limits", "CortexMeta")
    field("Requested URL", report["target"])
    field("Final observed URL", report["final_url"])
    p("Observation ID: " + report["id"], "CortexMeta")
    p("Observed at (UTC): " + report["generated_at"], "CortexMeta")
    field("Executive summary", " | ".join(f"{label}: {report['counts'].get(key, 0)}" for key, label in [("pass", "Passed checks"), ("fail", "Failed checks"), ("manual_review", "Manual review"), ("not_tested", "Not tested")]))
    p("These counts describe ten bounded checks, not a website security score. A pass applies only to the named observation. Manual review is not a failure. No device checks were run.")
    p("Scope and limitations", "Heading2")
    for item in report["limitations"]:
        p(item, "CortexMeta")
    story.append(PageBreak())
    p("Observed request route", "Heading1")
    for index, hop in enumerate(report["hops"], 1):
        p(f"Hop {index} / HTTP {hop['status']}", "Heading2")
        p(hop["url"])
        p("Connected public IP: " + hop["peer_ip"], "CortexMeta")
        p("TLS: " + ("; ".join(f"{k.replace('_', ' ').title()}: {v}" for k, v in hop["tls"].items()) if hop["tls"] else "Not used"), "CortexMeta")
        for key, value in hop["headers"].items():
            p(key, "Heading3")
            p(value, "CortexMeta")
    p("Evidence handling", "Heading2")
    p("Only selected headers are included (up to 3000 characters each); finding evidence is limited to 4000 characters. CSP nonces, cookie names/values and URL queries are redacted. This report is a snapshot, not a blockchain-attested artifact. Download does not contact the target again.")
    story.append(PageBreak())
    p("Findings and next steps", "Heading1")
    for finding in report["findings"]:
        p(f"{finding['id']} / {finding['title']}", "Heading2")
        p("Outcome: " + finding["verdict"].replace("_", " ").title(), "CortexOutcome")
        for key, title in [("evidence", "Observed evidence"), ("explanation", "Interpretation"), ("remediation", "Recommended action"), ("verification", "How to verify")]:
            field(title, finding[key])
        if finding["reference"]:
            p("Technical reference: " + finding["reference"], "CortexMeta")
        story.append(Spacer(1, 14))
    SimpleDocTemplate(buffer, pagesize=A4, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=48, title="Cortex website observation", author="Cortex").build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
