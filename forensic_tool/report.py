from __future__ import annotations
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from .logger import get_logger

logger = get_logger()


def export_csv(path: Path, rows: List[Dict[str, Any]]):
    if not rows:
        return
    headers = list(rows[0].keys())
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    logger.info(f"Report exported as CSV: {path}")


def export_json(path: Path, rows: List[Dict[str, Any]]):
    with path.open('w', encoding='utf-8') as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    logger.info(f"Report exported as JSON: {path}")


def export_pdf(path: Path, rows: List[Dict[str, Any]], title: str):
    doc = SimpleDocTemplate(str(path), pagesize=A4)
    styles = getSampleStyleSheet()

    story = []
    story.append(Paragraph(title, styles['Title']))
    story.append(Paragraph(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), styles['Normal']))
    story.append(Spacer(1, 12))

    # Summary
    total = len(rows)
    story.append(Paragraph(f"Total files scanned: {total}", styles['Heading3']))
    story.append(Spacer(1, 12))

    # Table
    if rows:
        headers = [
            'File Name', 'Path', 'Type', 'Category', 'Size', 'MD5', 'SHA256',
            'Signature Match', 'Entropy', 'Extension Mismatch', 'Threat Scan', 'Integrity Status'
        ]
        # Prepare data rows with safe get
        data = [headers]
        for r in rows:
            data.append([
                r.get('File Name',''), r.get('Path',''), r.get('Type',''), r.get('Category',''), r.get('Size',''),
                r.get('MD5',''), r.get('SHA256',''), r.get('Signature Match',''), r.get('Entropy',''),
                r.get('Extension Mismatch',''), r.get('Threat Scan',''), r.get('Integrity Status','')
            ])
        tbl = Table(data, repeatRows=1)
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#003366')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.lightgrey]),
            ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
        ]))
        story.append(tbl)

    doc.build(story)
    logger.info(f"Report exported as PDF: {path}")
