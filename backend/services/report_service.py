"""
Generates a PDF threat-intelligence summary report from the stored detections.
Uses fpdf2 (pure Python, no system dependencies).
"""
import io
from datetime import datetime, timedelta

from fpdf import FPDF
from models.database import get_all_threat_logs, get_all_soc_events, get_all_email_scans
from realtime import SEV_SCORE

# Brand palette (RGB)
NAVY   = (15, 23, 42)
TEAL   = (45, 212, 191)
SLATE  = (100, 116, 139)
RED    = (239, 68, 68)
AMBER  = (245, 158, 11)
GREEN  = (16, 185, 129)
LIGHT  = (230, 237, 243)


def _band_color(score):
    if score is None:
        return SLATE
    if score >= 70:
        return RED
    if score >= 40:
        return AMBER
    return GREEN


def _band_name(score):
    if score is None:
        return "Unknown"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


class _Report(FPDF):
    def header(self):
        self.set_fill_color(*NAVY)
        self.rect(0, 0, self.w, 26, "F")
        self.set_xy(12, 8)
        self.set_text_color(*TEAL)
        self.set_font("Helvetica", "B", 15)
        self.cell(0, 6, "Threat Intelligence Report", ln=1)
        self.set_x(12)
        self.set_text_color(*LIGHT)
        self.set_font("Helvetica", "", 8)
        self.cell(0, 4, "AI-Powered Security Operations Platform", ln=1)
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_text_color(*SLATE)
        self.set_font("Helvetica", "", 7)
        self.cell(0, 4, f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", align="L")
        self.cell(0, 4, f"Page {self.page_no()}/{{nb}}", align="R")

    def section_title(self, text):
        self.ln(2)
        self.set_text_color(*NAVY)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 7, text, ln=1)
        self.set_draw_color(*TEAL)
        self.set_line_width(0.6)
        self.line(self.get_x(), self.get_y(), self.get_x() + 40, self.get_y())
        self.ln(3)


def _fetch(days):
    cutoff = (datetime.utcnow().date() - timedelta(days=days - 1)).isoformat()
    urls = sorted(get_all_threat_logs(cutoff_date=cutoff),
                  key=lambda r: r.get("risk_score") or 0, reverse=True)[:40]
    soc = get_all_soc_events(cutoff_date=cutoff)[:40]
    emails = sorted(get_all_email_scans(cutoff_date=cutoff),
                    key=lambda r: r.get("phishing_score") or 0, reverse=True)[:40]
    return {"urls": urls, "soc": soc, "emails": emails}


def _clip(text, n):
    text = (text or "").replace("\n", " ")
    # fpdf core fonts are latin-1 only; drop anything outside it
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text if len(text) <= n else text[: n - 1] + "."


def generate(days: int = 7) -> bytes:
    data = _fetch(days)
    pdf = _Report(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    # Summary counts
    all_scores = (
        [r["risk_score"] for r in data["urls"]]
        + [r["phishing_score"] for r in data["emails"]]
        + [SEV_SCORE.get(r["severity"], 0) for r in data["soc"]]
    )
    total = len(all_scores)
    high = sum(1 for s in all_scores if (s or 0) >= 70)
    med = sum(1 for s in all_scores if 40 <= (s or 0) < 70)
    low = total - high - med

    pdf.set_text_color(*SLATE)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Reporting period: last {days} day(s)", ln=1)
    pdf.ln(2)

    # Summary cards
    cards = [("Total", total, NAVY), ("High", high, RED), ("Medium", med, AMBER), ("Low", low, GREEN)]
    cw = (pdf.w - 24 - 9) / 4
    x0 = pdf.get_x()
    y0 = pdf.get_y()
    for i, (label, val, color) in enumerate(cards):
        x = x0 + i * (cw + 3)
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(226, 232, 240)
        pdf.rect(x, y0, cw, 18, "DF")
        pdf.set_xy(x, y0 + 3)
        pdf.set_text_color(*color)
        pdf.set_font("Helvetica", "B", 17)
        pdf.cell(cw, 8, str(val), align="C")
        pdf.set_xy(x, y0 + 11)
        pdf.set_text_color(*SLATE)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(cw, 5, label, align="C")
    pdf.set_y(y0 + 24)

    # URL / QR detections
    pdf.section_title("URL & QR Detections")
    if data["urls"]:
        _table(pdf, ["Score", "Type", "Indicator", "Verdict"],
               [(str(r["risk_score"] if r["risk_score"] is not None else "-"),
                 (r["source_type"] or "").upper(),
                 _clip(r["input_value"], 60),
                 r["threat_label"] or "-",
                 r["risk_score"]) for r in data["urls"]],
               [16, 16, 110, 30])
    else:
        _empty(pdf)

    # SOC events
    pdf.section_title("SOC Log Events")
    if data["soc"]:
        _table(pdf, ["Severity", "Category", "Summary"],
               [(r["severity"].upper(),
                 _clip(r["category"], 24),
                 _clip(r["explanation"] or r["raw_log_line"], 80),
                 SEV_SCORE.get(r["severity"], 0)) for r in data["soc"]],
               [22, 40, 110])
    else:
        _empty(pdf)

    # Email scans
    pdf.section_title("Email Phishing Scans")
    if data["emails"]:
        _table(pdf, ["Score", "Sender", "Subject", "Verdict"],
               [(str(r["phishing_score"] if r["phishing_score"] is not None else "-"),
                 _clip(r["sender"], 30),
                 _clip(r["subject"], 50),
                 r["label"] or "-",
                 r["phishing_score"]) for r in data["emails"]],
               [16, 50, 76, 30])
    else:
        _empty(pdf)

    out = pdf.output()
    return bytes(out)


def _empty(pdf):
    pdf.set_text_color(*SLATE)
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 6, "No detections in this period.", ln=1)
    pdf.ln(2)


def _table(pdf, headers, rows, widths):
    # Header row
    pdf.set_fill_color(*NAVY)
    pdf.set_text_color(*LIGHT)
    pdf.set_font("Helvetica", "B", 8)
    for h, w in zip(headers, widths):
        pdf.cell(w, 7, " " + h, border=0, fill=True)
    pdf.ln(7)

    pdf.set_font("Helvetica", "", 8)
    for i, row in enumerate(rows):
        *cells, score = row
        # Zebra striping
        pdf.set_fill_color(*(248, 250, 252) if i % 2 == 0 else (255, 255, 255))
        # Colored score in first cell
        first = True
        for c, w in zip(cells, widths):
            if first:
                pdf.set_text_color(*_band_color(score))
                pdf.set_font("Helvetica", "B", 8)
            else:
                pdf.set_text_color(40, 40, 40)
                pdf.set_font("Helvetica", "", 8)
            pdf.cell(w, 6, " " + str(c), border="B", fill=True)
            first = False
        pdf.ln(6)
    pdf.ln(3)
