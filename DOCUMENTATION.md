# Automated File Forensics & Virus Scanner — Comprehensive Documentation

## Overview
A cross-platform (Windows + Ubuntu) GUI tool for file forensics and local threat scanning. It provides a modern PyQt5 interface to scan folders, analyze files, check for threats, and export detailed reports. The application is modular, extensible, and uses a local SQLite database for integrity tracking.


## Features

---

## Dummy File Generation for Testing

To facilitate comprehensive testing and dissertation results, a Python script (`create_dummy_files.py`) is provided to automatically generate 100–150 dummy files of various types in a structured folder (`dummy_test_files`).

- **File types generated:**
  - Images: JPEG, PNG, GIF
  - Documents: PDF, DOCX, TXT, CSV
  - Executables: EXE, DLL, ELF, SO
  - Archives: ZIP, RAR, 7z
  - Scripts: PY, BAT, SH
  - Audio/Video: MP3, MP4
  - Random binaries, high entropy files, files with no extension
  - Mixed/edge cases: mismatched extensions, empty files, large files, non-ASCII names
  - **Infected files:** EICAR test files and variants are placed in a dedicated `infected` folder for safe AV detection testing

- **How to use:**
  1. Run `create_dummy_files.py` in your project directory.
  2. The script will create a `dummy_test_files` folder with subfolders for each file type, including an `infected` folder.
  3. Use the application's GUI to scan these folders for demonstration, testing, and dissertation results.

- **Purpose:**
  - Ensures safe, repeatable, and comprehensive testing of all features (file type detection, metadata extraction, AV scanning, integrity tracking, error handling, etc.)
  - The `infected` folder allows you to demonstrate malware/threat detection capabilities using standard EICAR test files (recognized by most antivirus engines).

---

---

## Technologies Used
- **Python 3**
- **PyQt5** (GUI)
- **SQLite** (integrity database)
- **Pillow (PIL)** (image/EXIF)
- **PyPDF2** (PDF metadata)
- **python-magic / python-magic-bin** (file type detection)
- **pefile** (PE analysis, Windows)
- **lief** (ELF analysis, Linux)
- **reportlab** (PDF export)
- **python-dotenv** (env config)
- **pywin32** (Windows file owner/ACL)

---

## Setup & Installation
1. **Create/activate a virtual environment**
2. **Install dependencies:**
   - Windows: `pip install -r requirements.txt`
   - Ubuntu: `sudo apt-get install -y python3-pyqt5 libmagic1 && pip install -r requirements.txt`
3. *(Optional)* Set AV paths in `.env`:
   - `DEFENDER_MPCMDRUN_PATH` for Windows Defender
   - `CLAMSCAN_PATH` for ClamAV

---

## Usage
- **Run the app:**
  ```
  python main.py
  ```
- **Scan a folder:**
  - Click "Choose Folder and Scan" in the GUI.
- **View results:**
  - Results appear in a table; double-click for details.
- **Export:**
  - Use the export button to save results as CSV, JSON, or PDF.

---

## High-Level Architecture & Data Flow
1. **Startup:** `main.py` loads environment and logging, then launches the GUI.
2. **User selects a folder:** The GUI starts a scan in a worker thread.
3. **File analysis:** For each file:
   - `analyzer.py` and `metadata.py` extract type, hashes, entropy, metadata, etc.
   - `local_scanner.py` runs an AV scan and returns the result.
   - `db.py` checks the last known hash for integrity status.
4. **Results display:** Results are shown in a table, with details in a side panel and dialog.
5. **Export:** User can export results as CSV, JSON, or PDF using `report.py`.
6. **Logging:** All actions, errors, and per-file details are logged.

---

## File-by-File Details

### Top-Level Files

#### `main.py`
- **Purpose:** Entry point for the application.
- **How it works:**
  - Imports the GUI and logger modules from `forensic_tool`.
  - Tries to load environment variables from a `.env` file using `python-dotenv` (optional, for AV paths).
  - Initializes the logger (writes to both file and console).
  - Defines a `main()` function that logs startup, runs the GUI, and logs exit.
  - If run as a script, calls `main()`.
  - **Key function:** `main()`
  - **Integration:** This file is the only place where the application is started; all logic is in the package.

#### `requirements.txt`
- **Purpose:** Lists all required Python packages, with platform-specific dependencies for Windows and Linux.
- **Details:**
  - Includes PyQt5, Pillow, PyPDF2, python-magic, exifread, pefile, lief, reportlab, python-dotenv, pywin32.
  - Uses environment markers to install the correct packages for Windows or Linux (e.g., `python-magic-bin` for Windows, `python-magic` for Linux).

#### `README.md`
- **Purpose:** User-facing documentation, setup instructions, and feature summary.
- **Details:**
  - Explains features, setup, dependencies, and usage.
  - Describes AV integration, database, and reporting.

#### `forensics.db`
- **Purpose:** SQLite database for file hash history and integrity tracking.
- **Details:**
  - Created automatically in the working directory.
  - Table: `file_hashes` with columns: `id`, `path`, `md5`, `sha256`, `size`, `mtime`, `scanned_at`.
  - Used to track file integrity between scans (detects new, modified, unchanged files).
  - Accessed via the `ForensicDB` class in `db.py`.

---

### The `forensic_tool/` Package

#### `gui.py`
- **Purpose:** Implements the main PyQt5 GUI and all user interaction.
- **Key Features:**
  - Modern, themed interface (light/dark) with status bar, progress bar, and table.
  - Folder selection dialog, scan button, theme toggle, filter box, and export button.
  - Results table with columns for file name, path, type, category, size, hashes, signature, entropy, AV result, and integrity status.
  - Details panel shows full metadata, hashes, and analysis for the selected file.
  - Double-clicking a row opens a dialog with all details in HTML format.
  - Threaded scanning: uses a worker thread to scan files so the UI remains responsive.
  - Integrates with all analysis modules (`analyzer`, `metadata`, `local_scanner`), database (`db`), and reporting (`report`).
  - Exports results as CSV, JSON, or PDF (calls `export_csv`, `export_json`, `export_pdf`).
  - Logs all actions, including per-file details and user interactions, for auditability.
- **Key Classes/Functions:**
  - `ForensicGUI`: Main window class. Handles all UI logic, event handling, and data flow.
  - `ScanResult`: Data structure (dataclass) for each file’s scan result, including all analysis and metadata.
  - `Emitter`: Qt signal emitter for thread-safe communication between worker thread and UI.
  - `run_gui()`: Starts the PyQt5 application and shows the main window.
- **Implementation Notes:**
  - Uses PyQt5 widgets for all UI elements.
  - Maintains a list of `ScanResult` objects for the current scan.
  - Uses signals/slots to update the UI from the worker thread.
  - Handles AV status display, filtering, and exporting.
  - All per-file analysis is delegated to the analyzer and metadata modules.

#### `analyzer.py`
- **Purpose:** Core file analysis logic for all scanned files.
- **Key Features:**
  - Detects file type using magic numbers (first bytes of file, compared to known signatures).
  - Calculates Shannon entropy of file content (to detect compressed/encrypted files).
  - Computes MD5 and SHA256 hashes for integrity and identification.
  - Extracts EXIF metadata from images (JPEG, PNG, GIF) using Pillow.
  - Extracts PDF metadata using PyPDF2.
  - Analyzes Windows PE executables using `pefile` (sections, imports, suspicious entropy).
  - Analyzes Linux ELF executables using `lief` (sections, entry point, type).
  - Checks for extension/type mismatches (e.g., file named .jpg but is a PDF).
- **Key Functions:**
  - `analyze_file(path)`: Main entry point. Returns a dictionary with all analysis results for a file.
  - `calculate_entropy(sample)`: Calculates entropy for a byte sample.
  - `detect_file_type(path)`: Reads magic bytes and matches to known types.
  - `get_signature_hex(path)`: Returns the hex signature of the file's first bytes.
  - `hash_file(path, algo)`: Computes file hash (MD5/SHA256).
  - `extract_exif(path)`: Extracts EXIF metadata from images.
  - `extract_pdf_metadata(path)`: Extracts PDF metadata.
  - `analyze_pe(path)`: Analyzes PE executables for suspicious sections and imports.
  - `analyze_elf(path)`: Analyzes ELF executables for sections and entry point.
- **Implementation Notes:**
  - Handles missing dependencies gracefully (e.g., if `pefile` or `lief` not installed).
  - Returns all results as a dictionary for easy integration with the GUI and reporting.

#### `constants.py`
- **Purpose:** Centralized constants and configuration for the application.
- **Details:**
  - `MAGIC_SIGNATURES`: Dictionary mapping magic bytes to human-readable file types.
  - `FILE_CATEGORIES`: Maps file types to categories (Image, Document, Archive, Executable, etc.).
  - `HIGH_ENTROPY_THRESHOLD`: Entropy value above which a file is considered likely compressed/encrypted.
  - `DEFAULT_DB_NAME`, `LOG_DIR`, `LOG_FILE`: Filenames for database and logs.
  - `CLAMSCAN_ENV_VAR`, `DEFENDER_ENV_VAR`: Environment variable names for AV paths.
  - `CLAMSCAN_TIMEOUT`, `DEFENDER_TIMEOUT`: Timeouts for AV scans.
  - `APP_NAME`: Application name for display and logging.

#### `db.py`
- **Purpose:** SQLite wrapper for storing file hash history and integrity data.
- **Key Features:**
  - Ensures the database schema exists on first use (creates `file_hashes` table and index).
  - Thread-safe: uses a lock to allow safe access from multiple threads (e.g., GUI and worker thread).
  - Methods to insert new file hashes and retrieve the last hash for a file (to detect changes).
  - Can be extended for more advanced tracking (e.g., per-user, per-scan session).
- **Key Class:**
  - `ForensicDB`: Handles all DB operations.
    - `__init__`: Opens/creates the database.
    - `_ensure_schema`: Creates tables and indexes if missing.
    - `insert_file_hash`: Inserts a new hash record for a file.
    - `get_last_hash`: Gets the last known hash for a file path.
    - `close`: Closes the database connection.

#### `local_scanner.py`
- **Purpose:** Local antivirus (AV) integration for threat scanning.
- **Key Features:**
  - Detects and uses Microsoft Defender (Windows) or ClamAV (Linux) to scan files for malware.
  - Returns status: "Clean", "Infected: <signature>", "Not Available", "AV Disabled", or error messages.
  - Detects AV availability at runtime (checks for executables or environment variables).
  - Parses AV output to extract threat names or detection status.
  - Handles timeouts and errors gracefully.
- **Key Class:**
  - `LocalScanner`: Handles AV detection and scanning.
    - `__init__`: Configures AV paths and enables/disables scanning.
    - `availability`: Returns whether AV is available and which engine is used.
    - `scan_file`: Scans a file and returns a status string.
    - `_scan_with_defender`, `_scan_with_clam`: Internal methods to invoke AV engines and parse results.

#### `logger.py`
- **Purpose:** Configures logging for the application (file and console).
- **Key Features:**
  - Uses Python's `logging` module with a rotating file handler (max 1MB, 3 backups).
  - Logs to both file (`logs/forensic_tool.log`) and console.
  - Log format includes timestamp, log level, module, function, line number, and thread name.
  - `get_logger()` returns a singleton logger instance for use throughout the app.
  - Used for all info, debug, warning, and error messages in the app.

#### `metadata.py`
- **Purpose:** Cross-platform file metadata extraction (size, times, owner, permissions).
- **Key Features:**
  - On Windows: Uses `pywin32` to get file owner and ACL info (domain\user), and basic permissions.
  - On Linux: Uses `pwd` and `grp` to get UID/GID and username/group, and POSIX permissions.
  - Returns size, created/modified/accessed times, permissions (as string), and owner info.
  - Handles missing modules gracefully (returns "N/A" or "Unknown" if info not available).
  - Used by the GUI to display file metadata in the details panel.

#### `report.py`
- **Purpose:** Utilities for exporting scan results as reports.
- **Key Features:**
  - Exports results as CSV (comma-separated values), JSON (structured data), or PDF (formatted report).
  - PDF reports use `reportlab` to create a styled table and summary.
  - Handles Unicode and special characters in file names and metadata.
  - Used by the GUI's export button.
  - Logs export actions and errors.
  - Can be extended for more formats (e.g., HTML, XML).

---

### Other Files/Folders

#### `logs/forensic_tool.log`
- **Purpose:** Log file for all application actions, errors, and per-file details.
- **Details:**
  - Created automatically in the `logs/` directory.
  - Rotated when size exceeds 1MB (up to 3 backups).
  - Contains info, debug, warning, and error messages from all modules.

#### `__pycache__/`
- **Purpose:** Python bytecode cache (auto-generated).
- **Details:**
  - Contains `.pyc` files for faster module loading.
  - Safe to delete; will be regenerated by Python as needed.

---

## Extending & Troubleshooting
- **Add new file types:** Update `MAGIC_SIGNATURES` and `FILE_CATEGORIES` in `constants.py`, and extend `analyzer.py`.
- **Add new AV engines:** Extend `local_scanner.py` with new scan methods.
- **Debugging:** Check `logs/forensic_tool.log` for detailed error/info logs.
- **Database issues:** The app auto-creates the DB; delete `forensics.db` to reset history.

---

## Security & Platform Notes
- **No internet upload:** All scans and analysis are local.
- **Cross-platform:** Works on Windows and Linux, with platform-specific features.
- **Permissions:** On Windows, uses pywin32 for owner/ACL; on Linux, uses pwd/grp for UID/GID.

---

## Deep Dive: Data Flow and Integration

1. **Startup:**
   - `main.py` loads environment and logging, then launches the GUI.
2. **User selects a folder:**
   - `gui.py` opens a folder dialog, then starts a scan in a worker thread.
3. **File analysis:**
   - For each file, `analyzer.py` and `metadata.py` extract type, hashes, entropy, metadata, and more.
   - `local_scanner.py` runs an AV scan (Defender/ClamAV) and returns the result.
   - `db.py` checks the last known hash for integrity status (new/modified/unchanged).
4. **Results display:**
   - Results are shown in a table in the GUI, with details in a side panel and dialog.
5. **Export:**
   - User can export results as CSV, JSON, or PDF using `report.py`.
6. **Logging:**
   - All actions, errors, and per-file details are logged to `logs/forensic_tool.log`.

---

## Credits & License
- See `README.md` for authorship and license details.

---

