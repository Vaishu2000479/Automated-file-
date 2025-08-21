# Automated File Forensics & Virus Scanner

Cross-platform GUI tool for file forensics and local threat scanning.

---

## Features
- PyQt5 GUI: choose folder, progress bar, results table, double-click for details
- File type detection, entropy, hashes (MD5/SHA256)
- EXIF (images), PDF metadata; PE (Windows) via pefile, ELF (Linux) via LIEF
- Local AV integration (Windows Defender on Windows, ClamAV if available)
- SQLite integrity tracking between scans
- Export as CSV, JSON, PDF (ReportLab)
- Logging to `logs/forensic_tool.log`

---

## Installation & Usage

### Windows
1. **Install Python 3.8+** (from [python.org](https://www.python.org/downloads/)).
2. **Open Command Prompt or PowerShell** and navigate to the project directory.
3. **(Recommended) Create and activate a virtual environment:**
   ```
   python -m venv venv
   .\venv\Scripts\activate
   ```
4. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```
5. *(Optional)* To enable Windows Defender integration, you can set the path in a `.env` file:
   ```
   DEFENDER_MPCMDRUN_PATH=C:\Program Files\Windows Defender\MpCmdRun.exe
   ```
6. **Run the application:**
   ```
   python main.py
   ```

### Ubuntu (Linux)
1. **Install Python 3.8+** (usually pre-installed).
2. **Open Terminal** and navigate to the project directory.
3. **(Recommended) Create and activate a virtual environment:**
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```
4. **Install system dependencies:**
   ```
   sudo apt-get update
   sudo apt-get install -y python3-pyqt5 libmagic1 clamav
   ```
5. **Install Python dependencies:**
   ```
   pip install -r requirements.txt
   ```
6. *(Optional)* To enable ClamAV integration, you can set the path in a `.env` file:
   ```
   CLAMSCAN_PATH=/usr/bin/clamscan
   ```
7. **Run the application:**
   ```
   python main.py
   ```

---

## How to Use
1. Launch the application as described above.
2. Click **"Choose Folder and Scan"** to select a directory for scanning.
3. Wait for the scan to complete. Results will appear in the table.
4. Double-click any row for detailed file analysis.
5. Use the **Export** button to save results as CSV, JSON, or PDF.

---

## Notes
- On Windows, `pywin32` enables owner/ACL info; on Linux, UID/GID and rwx permissions are shown.
- LIEF is only installed on Linux by default (heavy package). On Windows you can skip ELF analysis.
- The SQLite DB `forensics.db` is created in the working directory.

## Reports
- CSV and JSON: raw data
- PDF: formatted table with summary

## Logging
- Logs are written to `logs/forensic_tool.log`
