# 🔍 EXE File Analyzer

[![GitHub](https://img.shields.io/badge/GitHub-piplarsson-blue)](https://github.com/piplarsson)
[![Version](https://img.shields.io/badge/Version-1.0.0-green)]()
[![Python](https://img.shields.io/badge/Python-3.6+-yellow)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue)]()
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

A powerful Python tool for analyzing Windows executable files (.exe) to detect programming languages, compilers, and extract detailed metadata.

## ✨ Features

- **Language & Compiler Detection**: Identifies C++, C#/.NET, Python, Go, Rust, Delphi, and more
- **Hash Calculation**: MD5, SHA1, and SHA256 checksums
- **Section Analysis**: Entropy calculation and characteristic analysis
- **Packer Detection**: Identifies UPX, ASPack, Themida, and other packers/protectors
- **Import/Export Analysis**: Lists all imported DLLs and exported functions
- **Resource Extraction**: Analyzes embedded resources (icons, versions, manifests, etc.)
- **String Extraction**: Finds URLs, file paths, registry keys, and interesting keywords
- **Anomaly Detection**: Identifies suspicious characteristics
- **Digital Signature Check**: Verifies if the file is digitally signed

## 📋 Requirements

- Python 3.6 or higher
- Windows OS (for analyzing Windows executables)

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/piplarsson/exe-file-analyzer.git
cd exe-file-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Command Line
```bash
python exe_analyzer.py path/to/your/file.exe
```

### Interactive Mode
```bash
python exe_analyzer.py
# Then enter the path when prompted
```

## 📊 Example Output

The analyzer provides detailed information in a formatted console output:

- Basic file information (size, hashes, compile time)
- Detected programming language/compiler
- PE sections with entropy analysis
- Imported DLLs and functions
- Embedded resources
- Extracted strings (URLs, paths, registry keys)
- Potential anomalies

## 🔧 Supported Languages/Compilers

- **Visual C++** (all versions from 6.0 to 2022)
- **C#/.NET Framework** (all versions)
- **Python** (PyInstaller, py2exe)
- **Go**
- **Rust**
- **Delphi/Borland**
- **MinGW/GCC**
- **AutoIt**
- **Java/JAR**
- **Electron/Node.js**
- **Qt Framework**

## 📦 Download Pre-built Binary

If you don't want to install Python, you can download the standalone .exe version from the [Releases](https://github.com/piplarsson/exe-file-analyzer/releases) page.

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests

## 📝 License

This project is open source. Feel free to use and modify as needed.

## 👨‍💻 Author

Created by **Piplarsson**

---

**Note**: This tool is for educational and analysis purposes. Always respect software licenses and copyrights when analyzing executable files.