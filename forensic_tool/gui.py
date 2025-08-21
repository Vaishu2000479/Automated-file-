from __future__ import annotations
import os
import threading
from dataclasses import dataclass
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from PyQt5 import QtWidgets, QtCore, QtGui

from .constants import APP_NAME
from .logger import get_logger
from .db import ForensicDB
from .local_scanner import LocalScanner
from .analyzer import analyze_file, get_signature_hex
from .metadata import get_metadata
from .report import export_csv, export_json, export_pdf

logger = get_logger()


# Lightweight theming (dark and light) with clear alternating rows and readable badges
DARK_STYLE = """
QMainWindow { background-color: #0b1220; color: #e5e7eb; }
QWidget { color: #e5e7eb; }
QStatusBar { background: #0b1220; color: #93a2b8; }
QTableWidget, QTableView {
    background: #111827;
    alternate-background-color: #0f172a;
    color: #e5e7eb;
    gridline-color: #1f2937;
    selection-background-color: #2563eb;
    selection-color: white;
}
QHeaderView::section {
    background: #0f172a; color: #e5e7eb; border: 0px; padding: 8px; font-weight: 600;
}
QFrame#Card { background: #0f172a; border: 1px solid #1f2937; border-radius: 10px; }
QPushButton {
    background: #1f2937; color: #e5e7eb; border: 1px solid #374151; padding: 8px 12px; border-radius: 6px;
}
QPushButton:hover { background: #374151; }
QLineEdit { background: #0f172a; border: 1px solid #374151; border-radius: 6px; padding: 6px 8px; color: #e5e7eb; }
QLabel#Badge { background: #1f2937; color: #e5e7eb; border: 1px solid #374151; border-radius: 12px; padding: 6px 10px; }
QTextEdit { background: #0f172a; color: #e5e7eb; }
"""

LIGHT_STYLE = """
QMainWindow { background-color: #f8fafc; color: #0f172a; }
QWidget { color: #0f172a; }
QStatusBar { background: #f8fafc; color: #475569; }
QTableWidget, QTableView {
  background: #ffffff;
  alternate-background-color: #f3f4f6;
  color: #0f172a;
  gridline-color: #e5e7eb;
  selection-background-color: #2563eb;
  selection-color: white;
}
QHeaderView::section {
  background: #e5e7eb; color: #0f172a; border: 0px; padding: 8px; font-weight: 600;
}
QFrame#Card { background: #ffffff; border: 1px solid #cbd5e1; border-radius: 10px; }
QPushButton { background: #e2e8f0; color: #0f172a; border: 1px solid #cbd5e1; padding: 8px 12px; border-radius: 6px; }
QPushButton:hover { background: #cbd5e1; }
QLineEdit { background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 6px 8px; color: #0f172a; }
QLabel#Badge { background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; border-radius: 12px; padding: 6px 10px; }
"""


@dataclass
class ScanResult:
    file_name: str
    path: str
    type: str
    category: str
    size: int
    md5: str
    sha256: str
    signature_match: str
    entropy: float
    extension_mismatch: bool
    av_result: str
    integrity_status: str
    extra: Dict[str, Any]


class Emitter(QtCore.QObject):
    append_row = QtCore.pyqtSignal(object)
    set_progress = QtCore.pyqtSignal(int)


class ForensicGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1600, 920)
        self.is_dark_theme = False
        self.setStyleSheet(LIGHT_STYLE)

        # Core
        self.db = ForensicDB()
        self.local_av = LocalScanner()

        # Status bar
        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)
        self.av_status = QtWidgets.QLabel()
        self.status.addPermanentWidget(self.av_status)

        # Root shell and top bar
        shell = QtWidgets.QWidget()
        root_layout = QtWidgets.QVBoxLayout(shell)
        root_layout.setContentsMargins(12, 12, 12, 12)

        top_bar = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel(APP_NAME)
        title.setStyleSheet("font-size: 18px; font-weight: 900;")
        self.scan_btn = QtWidgets.QPushButton("🔍  Scan Folder or File")
        self.scan_menu = QtWidgets.QMenu(self)
        self.scan_menu.addAction("Scan Folder", self.choose_and_scan_folder)
        self.scan_menu.addAction("Scan File", self.choose_and_scan_file)
        self.scan_btn.setMenu(self.scan_menu)
        self.theme_btn = QtWidgets.QPushButton("🌓  Toggle Theme")
        self.folder_label = QtWidgets.QLabel("No folder selected")
        self.folder_label.setStyleSheet("color: #93a2b8;")
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by name or path…")
        self.export_btn = QtWidgets.QPushButton("📤 Export Report")
        top_bar.addWidget(title)
        top_bar.addSpacing(8)
        top_bar.addWidget(self.scan_btn)
        top_bar.addWidget(self.theme_btn)
        top_bar.addWidget(self.folder_label, 1)
        top_bar.addWidget(QtWidgets.QLabel("Filter:"))
        top_bar.addWidget(self.filter_edit)
        top_bar.addWidget(self.export_btn)
        root_layout.addLayout(top_bar)

        # Main content
        main = QtWidgets.QWidget()
        mv = QtWidgets.QVBoxLayout(main)
        mv.setContentsMargins(0, 0, 0, 0)
        self.progress = QtWidgets.QProgressBar()
        self.progress.setValue(0)
        mv.addWidget(self.progress)

        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        # Table setup
        self.table = QtWidgets.QTableWidget(0, 12)
        self.table.setHorizontalHeaderLabels([
            'File Name', 'Path', 'Type', 'Category', 'Size', 'MD5', 'SHA256', 'Signature Match', 'Entropy',
            'Extension Mismatch', 'Threat Scan', 'Integrity Status'
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        # Larger cells/columns
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.horizontalHeader().setDefaultSectionSize(160)
        self.table.horizontalHeader().setMinimumSectionSize(100)
        self.table.itemSelectionChanged.connect(self._update_details_panel)
        self.table.doubleClicked.connect(self.show_details)

        # Details panel
        self.details_container = QtWidgets.QFrame()
        self.details_container.setObjectName("Card")
        dv = QtWidgets.QVBoxLayout(self.details_container)
        self.verdict_chip = QtWidgets.QLabel("—")
        self.verdict_chip.setAlignment(QtCore.Qt.AlignCenter)
        self.verdict_chip.setStyleSheet("padding: 14px; border-radius: 10px; font-size: 16px; font-weight: bold;")
        dv.addWidget(self.verdict_chip)
        badges = QtWidgets.QHBoxLayout()
        self.badge_entropy = self._badge("Entropy: —")
        self.badge_mismatch = self._badge("Mismatch: —")
        self.badge_integrity = self._badge("Integrity: —")
        badges.addWidget(self.badge_entropy)
        badges.addWidget(self.badge_mismatch)
        badges.addWidget(self.badge_integrity)
        badges.addStretch(1)
        dv.addLayout(badges)
        self.details = QtWidgets.QTextEdit()
        self.details.setReadOnly(True)
        self.details.setStyleSheet("font-family:'Consolas','Courier New',monospace; font-size:12px;")
        dv.addWidget(self.details, 1)

        split.addWidget(self.table)
        split.addWidget(self.details_container)
        split.setSizes([1100, 500])
        mv.addWidget(split)

        root_layout.addWidget(main, 1)
        self.setCentralWidget(shell)

        # Signals
        self.theme_btn.clicked.connect(self._toggle_theme)
    # self.scan_btn.clicked.connect(self.choose_and_scan)  # Now handled by menu actions
        self.export_btn.clicked.connect(self.export_report)
        self.filter_edit.textChanged.connect(self._apply_filter)

        # Data + status
        self.results = []
        self.current_root = None
        self.emitter = Emitter()
        self.emitter.append_row.connect(self._append_table_row)
        self.emitter.set_progress.connect(self._set_progress)
        self._update_av_status()

    def _badge(self, text: str) -> QtWidgets.QLabel:
        lbl = QtWidgets.QLabel(text)
        lbl.setObjectName("Badge")
        return lbl

    def _update_av_status(self):
        ok, where = self.local_av.availability()
        if ok:
            self.av_status.setText(f"AV: {where}")
            self.av_status.setStyleSheet("color: #10b981; font-weight: 700;")
        else:
            self.av_status.setText(f"AV: {where}")
            self.av_status.setStyleSheet("color: #ef4444; font-weight: 700;")

    def _apply_filter(self, text: str):
        text = text.strip().lower()
        for row in range(self.table.rowCount()):
            name_item = self.table.item(row, 0)
            path_item = self.table.item(row, 1)
            comb = f"{name_item.text()} {path_item.text()}".lower() if name_item and path_item else ""
            self.table.setRowHidden(row, text not in comb)


    def choose_and_scan_folder(self):
        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if directory:
            self.folder_label.setText(f"Scanning folder: {directory}")
            self.current_root = Path(directory)
            self.start_scan(self.current_root)

    def choose_and_scan_file(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File to Scan")
        if file_path:
            self.folder_label.setText(f"Scanning file: {file_path}")
            self.current_root = Path(file_path)
            self.start_scan(self.current_root)

    def start_scan(self, root: Path):
        self.current_root = root
        # Determine if root is a file or directory
        if root.is_file():
            files = [root]
            logger.info(f"Scan started for file {root}")
        else:
            logger.info(f"Scan started in folder {root}")
            files: List[Path] = []
            for dirpath, _dirs, filenames in os.walk(root):
                for name in filenames:
                    files.append(Path(dirpath) / name)
        total = len(files)
        if total == 0:
            QtWidgets.QMessageBox.information(self, "Scan", "No files found in the selected folder or file.")
            return

        self.progress.setValue(0)
        self.table.setRowCount(0)
        self.results.clear()
        self.details.clear()

        def worker():
            for idx, path in enumerate(files, start=1):
                try:
                    meta = get_metadata(path)
                    ana = analyze_file(path)
                    logger.info(f"File {path.name} scanned (SHA256: {ana.get('sha256','')})")

                    last = self.db.get_last_hash(str(path))
                    status = 'New'
                    if last:
                        _, last_sha = last
                        status = 'Modified' if last_sha != ana.get('sha256') else 'Unchanged'

                    av_res = self.local_av.scan_file(path)

                    try:
                        self.db.insert_file_hash(
                            str(path), ana.get('md5',''), ana.get('sha256',''), meta.get('size', 0),
                            path.stat().st_mtime, datetime.utcnow().isoformat()
                        )
                    except Exception as e:
                        logger.debug(f"DB insert failed for {path}: {e}")

                    row = ScanResult(
                        file_name=path.name,
                        path=str(path),
                        type=ana.get('type','Unknown'),
                        category=ana.get('category','Other'),
                        size=meta.get('size', 0),
                        md5=ana.get('md5',''),
                        sha256=ana.get('sha256',''),
                        signature_match='Yes' if ana.get('type','Unknown') != 'Unknown' else 'No',
                        entropy=ana.get('entropy', 0.0),
                        extension_mismatch=ana.get('extension_mismatch', False),
                        av_result=av_res,
                        integrity_status=status,
                        extra={
                            'metadata': meta,
                            'exif': ana.get('exif', {}),
                            'pdf_metadata': ana.get('pdf_metadata', {}),
                            'pe': ana.get('pe', {}),
                            'elf': ana.get('elf', {}),
                            'signature_hex': ana.get('signature_hex', get_signature_hex(path)),
                        }
                    )
                    # Log full per-file details for auditability and traceability
                    try:
                        full_details = self._result_to_full_row_dict(row)
                        logger.info(f"File details: {json.dumps(full_details, ensure_ascii=False)}")
                    except Exception as e:
                        logger.debug(f"Failed to log full details for {path.name}: {e}")
                    self.results.append(row)
                    self.emitter.append_row.emit(row)
                except Exception as e:
                    logger.error(f"Error scanning {path}: {e}")
                finally:
                    self.emitter.set_progress.emit(int(idx * 100 / total))
            logger.info("Scan finished")

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    @QtCore.pyqtSlot(int)
    def _set_progress(self, value: int):
        self.progress.setValue(value)
        self.progress.setFormat(f"{value}%")

    @QtCore.pyqtSlot(object)
    def _append_table_row(self, res: ScanResult):
        row = self.table.rowCount()
        self.table.insertRow(row)
        vals = [
            res.file_name,
            res.path,
            res.type,
            res.category,
            f"{res.size / 1024:.2f} KB" if res.size > 1024 else f"{res.size} B",
            res.md5,
            res.sha256,
            res.signature_match,
            f"{res.entropy:.4f}",
            "Yes" if res.extension_mismatch else "No",
            res.av_result,
            res.integrity_status,
        ]
        is_infected = isinstance(res.av_result, str) and res.av_result.lower().startswith("infected")
        for col, v in enumerate(vals):
            item = QtWidgets.QTableWidgetItem(v)
            if is_infected:
                item.setBackground(QtGui.QColor("#ef4444"))
                item.setForeground(QtGui.QColor("white"))
            elif res.integrity_status == 'Modified':
                item.setBackground(QtGui.QColor("#f59e0b"))
                item.setForeground(QtGui.QColor("black"))
            self.table.setItem(row, col, item)
        if row == 0:
            self.table.selectRow(0)

    def show_details(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.results):
            return
        res = self.results[row]
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(f"Details for {res.file_name}")
        dlg.resize(860, 740)
        layout = QtWidgets.QVBoxLayout(dlg)
        text = QtWidgets.QTextEdit()
        text.setReadOnly(True)
        text.setHtml(self._format_details_html(res))
        layout.addWidget(text)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)
        dlg.exec_()

    def _format_details_html(self, res: ScanResult) -> str:
        meta = res.extra.get('metadata', {}) or {}
        exif = res.extra.get('exif', {}) or {}
        pdfm = res.extra.get('pdf_metadata', {}) or {}

        def format_dict(d):
            return '<br>'.join([f"&nbsp;&nbsp;&nbsp;&nbsp;<b>{k}:</b> {v}" for k, v in d.items()])

        html = f"""
        <body style='font-family: Segoe UI, Arial, sans-serif; font-size: 14px;'>
            <h2 style='margin:0;'>{res.file_name}</h2>
            <p style='color:#64748b;'><b>Path:</b> {res.path}</p>
            <hr>
            <h3>File Analysis</h3>
            <p><b>Type:</b> {res.type}</p>
            <p><b>Category:</b> {res.category}</p>
            <p><b>Signature:</b> {res.extra.get('signature_hex', '')}</p>
            <p><b>Entropy:</b> {res.entropy:.4f} {'(High - likely compressed/encrypted)' if res.entropy >= 7.2 else ''}</p>
            <p><b>Extension Mismatch:</b> {'Yes' if res.extension_mismatch else 'No'}</p>
            <hr>
            <h3>Hashes & Integrity</h3>
            <p><b>MD5:</b> {res.md5}</p>
            <p><b>SHA256:</b> {res.sha256}</p>
            <p><b>Integrity Status:</b> {res.integrity_status}</p>
            <p><b>Threat Scan:</b> {res.av_result}</p>
            <hr>
            <h3>Metadata</h3>
            <p><b>Size:</b> {res.size} bytes</p>
            <p><b>Created:</b> {meta.get('created','N/A')}</p>
            <p><b>Modified:</b> {meta.get('modified','N/A')}</p>
            <p><b>Permissions:</b> {meta.get('permissions','N/A')}</p>
            <p><b>Owner:</b> {meta.get('owner','N/A')}</p>
        """
        if exif:
            html += f"<h3>EXIF Data</h3><p>{format_dict(exif)}</p>"
        if pdfm:
            html += f"<h3>PDF Metadata</h3><p>{format_dict(pdfm)}</p>"
        html += "</body>"
        return html

    def _update_details_panel(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.results):
            self.details.clear()
            self.verdict_chip.setText("—")
            self.verdict_chip.setStyleSheet("padding: 14px; border-radius: 10px; font-size: 16px; font-weight: bold;")
            self.badge_entropy.setText("Entropy: —")
            self.badge_mismatch.setText("Mismatch: —")
            self.badge_integrity.setText("Integrity: —")
            return
        res = self.results[row]
        # Log all details shown in the side panel for this file
        try:
            full_details = self._result_to_full_row_dict(res)
            logger.info(f"Details selected: {json.dumps(full_details, ensure_ascii=False)}")
        except Exception as e:
            logger.debug(f"Failed to log full details for {res.file_name}: {e}")
        self.details.setHtml(self._format_details_html(res))
        verdict = res.av_result or "—"
        chip_bg = "#1f2937"
        if verdict.startswith("Infected"):
            chip_bg = "#ef4444"
        elif verdict.startswith("Clean"):
            chip_bg = "#16a34a"
        elif verdict.startswith("AV Disabled"):
            chip_bg = "#f59e0b"
        self.verdict_chip.setText(f"Threat Scan: {verdict}")
        self.verdict_chip.setStyleSheet(
            f"padding: 14px; border-radius: 10px; background: {chip_bg}; font-size: 16px; font-weight: bold; color: white;"
        )
        self.badge_entropy.setText(f"Entropy: {res.entropy:.2f}")
        self.badge_mismatch.setText(f"Mismatch: {'Yes' if res.extension_mismatch else 'No'}")
        self.badge_integrity.setText(f"Integrity: {res.integrity_status}")

    def _toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.setStyleSheet(DARK_STYLE if self.is_dark_theme else LIGHT_STYLE)

    # settings UI removed per user request; advanced users can still set .env

    def _result_to_full_row_dict(self, r: ScanResult) -> Dict[str, Any]:
        meta = r.extra.get('metadata', {}) or {}
        exif = r.extra.get('exif', {}) or {}
        pdfm = r.extra.get('pdf_metadata', {}) or {}
        pe = r.extra.get('pe', {}) or {}
        elf = r.extra.get('elf', {}) or {}
        signature_hex = r.extra.get('signature_hex', '')
        size_human = f"{r.size / 1024:.2f} KB" if r.size > 1024 else f"{r.size} B"
        # Build a comprehensive, ordered row matching the side panel
        return {
            # Basic identifiers
            'File': r.file_name,  # alias for convenience (e.g., "file: 1x.csv")
            'File Name': r.file_name,
            'Path': r.path,
            # Analysis summary
            'File Analysis.Type': r.type,
            'File Analysis.Category': r.category,
            'File Analysis.Signature': signature_hex,
            'File Analysis.Entropy': f"{r.entropy:.4f}",
            'File Analysis.Extension Mismatch': 'No' if not r.extension_mismatch else 'Yes',
            # Hashes & Integrity
            'Hashes & Integrity.MD5': r.md5,
            'Hashes & Integrity.SHA256': r.sha256,
            'Hashes & Integrity.Integrity Status': r.integrity_status,
            'Hashes & Integrity.Threat Scan': r.av_result,
            # Metadata block
            'Metadata.Size': f"{r.size} bytes",
            'Metadata.Created': meta.get('created', ''),
            'Metadata.Modified': meta.get('modified', ''),
            'Metadata.Permissions': meta.get('permissions', ''),
            'Metadata.Owner': meta.get('owner', ''),
            # Additional fields preserved for completeness
            'Category': r.category,
            'Size Bytes': r.size,
            'Size Human': size_human,
            'Signature Match': r.signature_match,
            'Signature': signature_hex,
            'Signature Hex': signature_hex,
            'Type': r.type,
            'MD5': r.md5,
            'SHA256': r.sha256,
            'Entropy': f"{r.entropy:.4f}",
            'Extension Mismatch': 'Yes' if r.extension_mismatch else 'No',
            'Threat Scan': r.av_result,
            'Integrity Status': r.integrity_status,
            'Created': meta.get('created', ''),
            'Modified': meta.get('modified', ''),
            'Permissions': meta.get('permissions', ''),
            'Owner': meta.get('owner', ''),
            'EXIF': json.dumps(exif, ensure_ascii=False),
            'PDF Metadata': json.dumps(pdfm, ensure_ascii=False),
            'PE': json.dumps(pe, ensure_ascii=False),
            'ELF': json.dumps(elf, ensure_ascii=False),
        }

    def export_report(self):
        if not self.results:
            QtWidgets.QMessageBox.information(self, "Export", "No results to export.")
            return
        if not self.current_root:
            QtWidgets.QMessageBox.information(self, "Export", "Select a folder and run a scan first.")
            return
        try:
            out_path = self.current_root / f"{self.current_root.name}.csv"
            rows = [self._result_to_full_row_dict(r) for r in self.results]
            export_csv(out_path, rows)
            QtWidgets.QMessageBox.information(self, "Export", f"CSV exported to:\n{out_path}")
        except Exception as e:
            logger.error(f"Export failed: {e}")
            QtWidgets.QMessageBox.critical(self, "Export", f"Export failed: {e}")


def run_gui():
    app = QtWidgets.QApplication([])
    window = ForensicGUI()
    window.show()
    return app.exec_()