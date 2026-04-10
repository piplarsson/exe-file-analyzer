# EXE File Analyzer

[![GitHub](https://img.shields.io/badge/GitHub-piplarsson-blue)](https://github.com/piplarsson)
[![Version](https://img.shields.io/badge/Version-2.0.0-green)]()
[![Python](https://img.shields.io/badge/Python-3.8+-yellow)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue)]()
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

A Python GUI tool for static analysis of Windows PE files. Extracts metadata, detects compilers and packers, and displays extracted strings from the target executable.

## Features

- **Language & Compiler Detection** — Identifies Visual C++, C#/.NET, Python, Go, Rust, Delphi, MinGW/GCC, AutoIt, Java, Electron, and Qt, with version specifics where determinable
- **Hash Calculation** — MD5, SHA1, and SHA256 checksums
- **Section Analysis** — Per-section entropy, raw/virtual sizes, flags, and MD5; high-entropy sections are highlighted
- **Packer & Protector Detection** — Signature-based detection of UPX, ASPack, Themida, VMProtect, and others
- **Import Analysis** — Lists all imported DLLs and their functions; click a DLL to inspect its imports
- **Export Analysis** — Full list of exported function names
- **Resource Extraction** — Embedded resource types with item counts and total sizes
- **String Extraction** — All ASCII and UTF-16 strings extracted and categorised (URLs, paths, registry keys, emails, keywords); filterable by text and category
- **Anomaly Detection** — Flags suspicious PE properties such as zeroed timestamps, unusual section names, and entry points outside `.text`
- **Digital Signature Check** — Indicates whether the file carries an Authenticode signature

## Requirements

- Python 3.8 or higher
- `pefile` (see `requirements.txt`)
- `tkinter` (included with the standard Python Windows installer)

## Installation

```bash
git clone https://github.com/piplarsson/exe-file-analyzer.git
cd exe-file-analyzer
pip install -r requirements.txt
```

## Usage

Launch the GUI:

```bash
python exe_analyzer.py
```

Optionally pass a file path as an argument to pre-populate the path field:

```bash
python exe_analyzer.py C:\path\to\target.exe
```

Use the **Browse** button or type the path directly, then click **Analyze**. Results appear across the tabbed interface once analysis completes.

## Interface

| Tab | Contents |
|---|---|
| Overview | File metadata, hashes, compile timestamp, architecture, language/compiler, packer detection, version resource, digital signature |
| Strings | All extracted strings with category filter and text search |
| Imports | DLL list with per-DLL function view |
| Exports | Exported function names |
| Sections | PE section details with entropy highlighting |
| Resources | Embedded resource types, counts, and sizes |
| Anomalies | Suspicious PE characteristics |

## Supported Compilers / Runtimes

Visual C++ (6.0 – 2022), C#/.NET Framework, Python (PyInstaller, py2exe), Go, Rust, Delphi/Borland, MinGW/GCC, AutoIt, NSIS, Java/JAR, Electron/Node.js, Qt Framework

## License

MIT — see [LICENSE](LICENSE) for details.

## Author

Created by **Piplarsson**
Modified by **SparksSkywere**

---

This tool is intended for educational and research purposes. Always ensure you have appropriate authorisation before analysing third-party software.