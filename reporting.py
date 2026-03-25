from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def build_pdf(df, out_path):
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out), pagesize=A4)
    y = A4[1] - 45
    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Hybrid Phishing Detection Report")
    y -= 24
    c.setFont("Helvetica", 10)
    for _, row in df.iterrows():
        line = f"{row['timestamp']} | {row['input_type']} | {row['prediction']} | {row['confidence']:.3f}"
        c.drawString(40, y, line[:110])
        y -= 16
        if y < 60:
            c.showPage()
            y = A4[1] - 45
            c.setFont("Helvetica", 10)
    c.save()
    return str(out)
