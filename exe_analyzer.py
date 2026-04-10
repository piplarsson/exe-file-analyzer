# exe_analyzer.py
import pefile
import sys
import os
import re
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

# Analysis engine
class ExeAnalyzer:

    # Byte signatures used to identify the compiler or runtime.
    SIGNATURES = {
        'Visual C++': [
            b'Microsoft Visual C++', b'MSVCRT', b'_CRT_INIT',
            b'__CxxFrameHandler', b'Visual Studio',
        ],
        'Visual Basic': [
            b'VB5!', b'VB6', b'MSVBVM60.DLL', b'__vbaStrCmp', b'__vbaVarTstEq',
        ],
        'Delphi': [
            b'Borland', b'Delphi', b'TForm', b'TApplication',
            b'System@@LStrCmp', b'FastMM',
        ],
        '.NET/C#': [
            b'mscoree.dll', b'_CorExeMain', b'mscorlib',
            b'.NETFramework', b'System.Runtime',
        ],
        'Python': [
            b'python', b'PyInstaller', b'pyi-windows-manifest-filename',
            b'Py_Initialize', b'PyEval_', b'py2exe',
        ],
        'Go': [
            b'Go build ID:', b'runtime.gopanic', b'runtime.main',
            b'go.buildid', b'golang.org',
        ],
        'Rust': [
            b'rust_panic', b'rust_begin_unwind', b'cargo', b'rustc',
        ],
        'MinGW/GCC': [
            b'mingw', b'__mingw', b'libgcc', b'__gcc', b'GNU C',
        ],
        'AutoIt': [
            b'AutoIt v3', b'AU3!', b'AutoIt3ExecuteLine', b'AutoItSC',
        ],
        'NSIS Installer': [
            b'Nullsoft', b'NSIS', b'nsis.sf.net', b'NSIS.Library',
        ],
        'Java/JAR': [b'java', b'jar', b'JVM', b'javaw.exe'],
        'Electron/Node.js': [b'Electron', b'node.dll', b'chromium'],
        'Qt Framework': [b'Qt5Core', b'Qt6Core', b'QtCore4', b'qwindows'],
    }

    # Known packer / protector signatures.
    PACKERS = {
        'UPX':       [b'UPX!', b'UPX0', b'UPX1'],
        'ASPack':    [b'ASPack', b'.aspack'],
        'PECompact': [b'PECompact', b'PEC2'],
        'Themida':   [b'Themida', b'.themida'],
        'VMProtect': [b'.vmp0', b'.vmp1', b'VMProtect'],
        'Enigma':    [b'Enigma', b'enigma1'],
        'MPRESS':    [b'MPRESS', b'.MPRESS'],
        'Petite':    [b'petite', b'.petite'],
        'FSG':       [b'FSG!', b'FSG v'],
        'MEW':       [b'MEW', b'MEW11'],
    }

    # Mapping of PE resource type IDs to human-readable names (from WinUser.h).
    RESOURCE_TYPES = {
        1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG',
        6: 'STRING', 7: 'FONTDIR', 8: 'FONT', 9: 'ACCELERATOR',
        10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR',
        14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE',
        19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON',
        23: 'HTML', 24: 'MANIFEST',
    }

    # PE OPTIONAL_HEADER.Subsystem values from the Windows PE specification.
    SUBSYSTEMS = {
        1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
        5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE GUI',
        10: 'EFI Application', 11: 'EFI Boot Service Driver',
        12: 'EFI Runtime Driver', 13: 'EFI ROM',
        14: 'Xbox', 16: 'Windows Boot Application',
    }

    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.file_content = None

    def load_file(self):
        # Reads the file into memory and parses it as a PE image.
        try:
            with open(self.filepath, 'rb') as fh:
                self.file_content = fh.read()
            # Parse from the in-memory bytes so pefile doesn't re-open the file.
            self.pe = pefile.PE(data=self.file_content)
            return True
        except Exception as exc:
            raise RuntimeError(f"Cannot load file: {exc}") from exc

    def get_basic_info(self):
        # Returns file-level metadata for the Overview tab.
        info = {}
        info['Filename']  = os.path.basename(self.filepath)
        info['File Size'] = f"{os.path.getsize(self.filepath):,} bytes"
        info['MD5']       = hashlib.md5(self.file_content).hexdigest()
        info['SHA1']      = hashlib.sha1(self.file_content).hexdigest()
        info['SHA256']    = hashlib.sha256(self.file_content).hexdigest()

        if self.pe:
            try:
                ts = self.pe.FILE_HEADER.TimeDateStamp
                info['Compiled'] = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
            except (OSError, OverflowError, ValueError):
                info['Compiled'] = 'Invalid timestamp'

            machine = self.pe.FILE_HEADER.Machine
            arch_map = {0x14c: '32-bit (x86)', 0x8664: '64-bit (x64)',
                        0x1c0: 'ARM', 0xaa64: 'ARM64'}
            info['Architecture'] = arch_map.get(machine, f'Unknown (0x{machine:04x})')

            subsystem = self.pe.OPTIONAL_HEADER.Subsystem
            info['Subsystem'] = self.SUBSYSTEMS.get(subsystem, f'Unknown ({subsystem})')

            info['Entry Point']    = f"0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}"
            info['Image Base']     = f"0x{self.pe.OPTIONAL_HEADER.ImageBase:08x}"
            info['Linker Version'] = (f"{self.pe.OPTIONAL_HEADER.MajorLinkerVersion}."
                                      f"{self.pe.OPTIONAL_HEADER.MinorLinkerVersion}")
            info['OS Version']     = (f"{self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}."
                                      f"{self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}")
            info['Sections']       = str(self.pe.FILE_HEADER.NumberOfSections)

        return info

    def get_sections_info(self):
        # Returns a list of dicts describing each PE section.
        if not self.pe:
            return []
        sections = []
        for sec in self.pe.sections:
            name = sec.Name.decode('utf-8', errors='replace').rstrip('\x00')
            chars = sec.Characteristics
            # Decode the Characteristics bitmask into readable flag names.
            flags = []
            if chars & 0x20:         flags.append('CODE')
            if chars & 0x40:         flags.append('INIT_DATA')
            if chars & 0x80:         flags.append('UNINIT_DATA')
            if chars & 0x20000000:   flags.append('EXEC')
            if chars & 0x40000000:   flags.append('READ')
            if chars & 0x80000000:   flags.append('WRITE')
            sections.append({
                'name':           name,
                'virtual_address': f"0x{sec.VirtualAddress:08x}",
                'virtual_size':   sec.Misc_VirtualSize,
                'raw_size':       sec.SizeOfRawData,
                'entropy':        sec.get_entropy(),
                'md5':            sec.get_hash_md5(),
                'flags':          ', '.join(flags),
            })
        return sections

    def detect_packers(self):
        # Scans for known packer signatures and high-entropy sections.
        results = []
        if not self.file_content:
            return results
        lower = self.file_content.lower()
        for name, sigs in self.PACKERS.items():
            if any(s.lower() in lower for s in sigs):
                results.append(name)
        if self.pe:
            total = len(self.pe.sections)
            high  = sum(1 for s in self.pe.sections if s.get_entropy() > 7.0)
            # Treat ≥50 % of sections being high-entropy as suspicious.
            if total and high / total >= 0.5:
                results.append('Unknown packer (high entropy)')
        return results

    def get_version_info(self):
        # Extracts key-value strings from the PE version resource (VS_VERSION_INFO).
        info = {}
        if not self.pe:
            return info
        if not hasattr(self.pe, 'FileInfo'):
            return info
        for block in self.pe.FileInfo:
            if hasattr(block, 'StringTable'):
                for table in block.StringTable:
                    for k, v in table.entries.items():
                        key = k.decode('utf-8', errors='replace')
                        val = v.decode('utf-8', errors='replace')
                        info[key] = val
        return info

    def is_signed(self):
        # Returns True if the PE contains an Authenticode security directory entry.
        return hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY') if self.pe else False

    def get_imports(self):
        # Returns a dict of {dll_name: [function_name, ...]} from the import table.
        imports = {}
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='replace')
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode('utf-8', errors='replace'))
                else:
                    funcs.append(f'Ordinal {imp.ordinal}')
            imports[dll] = funcs
        return imports

    def get_exports(self):
        # Returns a list of exported function names from the export directory.
        exports = []
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8', errors='replace'))
        return exports

    def get_resources(self):
        # Returns a list of dicts describing each resource type, count, and total size.
        resources = []
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources
        for rtype in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_id   = getattr(rtype, 'id', None)
            type_name = self.RESOURCE_TYPES.get(type_id, f'TYPE_{type_id}') if type_id else '(named)'
            count = 0
            size  = 0
            if hasattr(rtype, 'directory'):
                for rid in rtype.directory.entries:
                    if hasattr(rid, 'directory'):
                        for rlang in rid.directory.entries:
                            if hasattr(rlang, 'data'):
                                count += 1
                                size  += rlang.data.struct.Size
            resources.append({'type': type_name, 'count': count, 'size': size})
        return resources

    def detect_compiler(self):
        # Identifies the compiler/runtime using two passes:
        if not self.pe or not self.file_content:
            return []
        detected = []
        lower = self.file_content.lower()

        # Import table — precise version identification.
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='replace').lower()
                if 'msvcr' in dll or 'msvcp' in dll:
                    m = re.search(r'(\d+)', dll)
                    ver_map = {
                        '140': '2015-2022', '120': '2013', '110': '2012',
                        '100': '2010', '90': '2008', '80': '2005',
                        '71': '2003', '70': '2002', '60': '6.0',
                    }
                    suffix = ver_map.get(m.group(1), m.group(1)) if m else ''
                    label  = f'Visual C++ {suffix}' if suffix else 'Visual C++'
                    if label not in detected:
                        detected.append(label)
                elif 'mscoree' in dll:
                    # mscoree.dll is the .NET CLR entry shim.
                    clr = self._get_clr_version()
                    label = f'.NET/C# ({clr})' if clr else '.NET/C#'
                    if label not in detected:
                        detected.append(label)

        # Raw byte signature scan with hit counting.
        confidence = {}
        for lang, patterns in self.SIGNATURES.items():
            hits = sum(1 for p in patterns if p.lower() in lower)
            if hits:
                confidence[lang] = hits

        # Avoid re-reporting languages already identified in pass 1.
        existing_prefixes = {d.split()[0] for d in detected}
        for lang, score in sorted(confidence.items(), key=lambda x: -x[1]):
            if score >= 2 and lang.split()[0] not in existing_prefixes:
                level = 'high' if score >= 3 else 'medium'
                detected.append(f'{lang} (confidence: {level})')

        return detected

    def _get_clr_version(self):
        # Searches raw bytes for the CLR version string embedded in the .NET metadata header.
        clr_map = {
            b'v4.0.30319': '.NET 4.x',
            b'v2.0.50727': '.NET 2.0/3.x',
            b'v1.1.4322':  '.NET 1.1',
            b'v1.0.3705':  '.NET 1.0',
        }
        for pat, ver in clr_map.items():
            if pat in self.file_content:
                return ver
        return None

    def get_strings(self, min_length=6):
        # Extracts printable strings via two passes:
        result = {
            'all': [],
            'urls': [],
            'emails': [],
            'paths': [],
            'registry': [],
            'interesting': [],
        }
        if not self.file_content:
            return result

        # Keywords that may indicate credentials or security-relevant content.
        interesting_kw = [
            'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
            'debug', 'error', 'warning', 'copyright', 'license', 'serial',
            'version', 'username', 'admin',
        ]

        seen = set()

        # ASCII strings — standard 7-bit printable characters.
        for raw in re.findall(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}',
                              self.file_content):
            s = raw.decode('ascii', errors='ignore').strip()
            if not s or s in seen:
                continue
            seen.add(s)
            row = {'value': s, 'encoding': 'ASCII'}
            result['all'].append(row)
            _categorise(s, row, result, interesting_kw)

        # UTF-16 LE strings — each character is printable + 0x00.
        for raw in re.findall(rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}',
                              self.file_content):
            try:
                s = raw.decode('utf-16-le', errors='ignore').strip()
            except Exception:
                continue
            if not s or s in seen:
                continue
            seen.add(s)
            row = {'value': s, 'encoding': 'UTF-16'}
            result['all'].append(row)
            _categorise(s, row, result, interesting_kw)

        return result

    def get_arguments(self):
        # Extracts command-line argument patterns from the binary's string content.
        if not self.file_content:
            return []
        args = set()
        pattern = rb'(?:--[a-zA-Z][a-zA-Z0-9_\-]{1,30}|-[a-zA-Z][a-zA-Z0-9_\-]{0,30}(?=\s|=|\x00)|/[A-Z][A-Z0-9_]{1,15}(?=\s|:|\x00))'
        for raw in re.findall(pattern, self.file_content):
            s = raw.decode('ascii', errors='ignore').strip().rstrip('=: ')
            if s:
                args.add(s)
        return sorted(args)

    def get_anomalies(self):
        # Checks for suspicious PE characteristics:
        anomalies = []
        if not self.pe:
            return anomalies

        ts = self.pe.FILE_HEADER.TimeDateStamp
        if ts == 0:
            anomalies.append('Timestamp is zero — possible tampering')
        elif ts > 2_147_483_647:
            # 0x7FFFFFFF is the maximum valid 32-bit POSIX timestamp (~2038).
            anomalies.append('Timestamp is in the future — suspicious')

        for sec in self.pe.sections:
            name = sec.Name.decode('utf-8', errors='replace').rstrip('\x00')
            if not name:
                anomalies.append('Section found with empty name')
            elif not name.startswith('.'):
                anomalies.append(f'Non-standard section name: {name!r}')
            if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
                anomalies.append(f'Section {name!r}: zero raw size but virtual size > 0')
            ent = sec.get_entropy()
            if ent > 7.5:
                anomalies.append(f'Section {name!r}: very high entropy ({ent:.2f}) — may be packed/encrypted')

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            anomalies.append('No import table — unusual for most executables')

        # Locate which section contains the entry point and warn if unexpected.
        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for sec in self.pe.sections:
            va  = sec.VirtualAddress
            vsz = sec.Misc_VirtualSize
            if va <= ep < va + vsz:
                name = sec.Name.decode('utf-8', errors='replace').rstrip('\x00')
                if name not in ('.text', '.code', 'CODE', 'UPX0', 'UPX1'):
                    anomalies.append(f'Entry point is in section {name!r} — unusual')
                break

        return anomalies

    def run_full_analysis(self):
        # Runs all analysis methods and returns a single result dict.
        self.load_file()
        return {
            'basic':     self.get_basic_info(),
            'version':   self.get_version_info(),
            'compiler':  self.detect_compiler(),
            'packers':   self.detect_packers(),
            'sections':  self.get_sections_info(),
            'imports':   self.get_imports(),
            'exports':   self.get_exports(),
            'resources': self.get_resources(),
            'strings':   self.get_strings(),
            'arguments': self.get_arguments(),
            'anomalies': self.get_anomalies(),
            'signed':    self.is_signed(),
        }

# Assigns a category tag to an extracted string and appends it to the appropriate list.
def _categorise(s, row, result, interesting_kw):
    lower = s.lower()
    if re.match(r'https?://', s) or re.match(r'ftp://', s):
        result['urls'].append(row)
        row['category'] = 'URL'
    elif re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', s):
        result['emails'].append(row)
        row['category'] = 'Email'
    elif re.search(r'HKEY_|Software\\|SYSTEM\\', s):
        result['registry'].append(row)
        row['category'] = 'Registry'
    elif '\\' in s or re.match(r'[a-zA-Z]:/', s) or s.startswith('/'):
        result['paths'].append(row)
        row['category'] = 'Path'
    else:
        row['category'] = ''

    # Secondary check: flag strings containing security-sensitive keywords.
    for kw in interesting_kw:
        if kw in lower:
            result['interesting'].append(row)
            if not row['category']:
                row['category'] = 'Interesting'
            break

# GUI

# Colour palette — Catppuccin Mocha tones chosen for readability on dark
# backgrounds and compliance with WCAG AA contrast ratios where practical.
DARK_BG   = '#1e1e2e'   # window / notebook background
PANEL_BG  = '#2a2a3e'   # card / panel background
ACCENT    = '#89b4fa'   # headings, tab labels, column headers
FG        = '#cdd6f4'   # primary text
FG_DIM    = '#6c7086'   # secondary / label text
GREEN     = '#a6e3a1'   # positive indicators (signed, no anomalies)
YELLOW    = '#f9e2af'   # medium-severity warnings (medium entropy)
RED       = '#f38ba8'   # high-severity warnings (high entropy, interesting strings)
CYAN      = '#89dceb'   # URL strings

MONO_FONT = ('Consolas', 9)       # used for data values
UI_FONT   = ('Segoe UI', 9)       # used for labels and controls
BOLD_FONT = ('Segoe UI', 9, 'bold')

# Main application window.
class ExeAnalyzerApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title('EXE File Analyzer')
        self.configure(bg=DARK_BG)
        self.geometry('1100x750')
        self.minsize(800, 600)
        self._results = None   # holds the last completed analysis dict
        self._build_styles()
        self._build_ui()

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use('clam')

        style.configure('TFrame', background=DARK_BG)
        style.configure('Panel.TFrame', background=PANEL_BG)
        style.configure('TLabel', background=DARK_BG, foreground=FG, font=UI_FONT)
        style.configure('Header.TLabel', background=DARK_BG, foreground=ACCENT, font=BOLD_FONT)
        style.configure('Dim.TLabel', background=DARK_BG, foreground=FG_DIM, font=UI_FONT)
        style.configure('Good.TLabel', background=DARK_BG, foreground=GREEN, font=UI_FONT)
        style.configure('Bad.TLabel',  background=DARK_BG, foreground=RED,   font=UI_FONT)

        style.configure('TButton', background=ACCENT, foreground=DARK_BG,
                        font=BOLD_FONT, borderwidth=0, focusthickness=0)
        style.map('TButton',
                  background=[('active', '#74c7ec'), ('pressed', '#89b4fa')],
                  foreground=[('active', DARK_BG)])

        style.configure('TEntry', fieldbackground=PANEL_BG, foreground=FG,
                        insertcolor=FG, borderwidth=1, relief='flat')

        style.configure('TNotebook', background=DARK_BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=PANEL_BG, foreground=FG_DIM,
                        font=UI_FONT, padding=(12, 5))
        style.map('TNotebook.Tab',
                  background=[('selected', DARK_BG)],
                  foreground=[('selected', ACCENT)])

        style.configure('Treeview', background=PANEL_BG, fieldbackground=PANEL_BG,
                        foreground=FG, font=MONO_FONT, rowheight=20, borderwidth=0)
        style.configure('Treeview.Heading', background=DARK_BG, foreground=ACCENT,
                        font=BOLD_FONT, borderwidth=0)
        style.map('Treeview',
                  background=[('selected', '#313244')],
                  foreground=[('selected', FG)])

        style.configure('TScrollbar', background=PANEL_BG, troughcolor=DARK_BG,
                        borderwidth=0, arrowcolor=FG_DIM)

        style.configure('Separator.TFrame', background='#313244')

    def _build_ui(self):
        # Top bar — file path entry and Browse button; analysis starts automatically on browse.
        top = ttk.Frame(self)
        top.pack(fill='x', padx=12, pady=(10, 6))

        ttk.Label(top, text='EXE File Analyzer', style='Header.TLabel',
                  font=('Segoe UI', 14, 'bold')).pack(side='left')

        ttk.Button(top, text='Browse…', command=self._browse).pack(side='right')

        self._path_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self._path_var, width=60)
        entry.pack(side='right', padx=6)
        ttk.Label(top, text='File:', style='Dim.TLabel').pack(side='right')

        # Status bar at the bottom of the window.
        self._status_var = tk.StringVar(value='Select a PE file to begin.')
        status_bar = ttk.Frame(self, style='Panel.TFrame', height=24)
        status_bar.pack(fill='x', side='bottom')
        ttk.Label(status_bar, textvariable=self._status_var,
                  background=PANEL_BG, foreground=FG_DIM,
                  font=UI_FONT).pack(side='left', padx=8, pady=3)

        self._progress = ttk.Progressbar(status_bar, mode='indeterminate', length=120)
        self._progress.pack(side='right', padx=8, pady=3)

        # Notebook
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill='both', expand=True, padx=12, pady=(0, 6))

        self._tab_overview  = self._make_tab('Overview')
        self._tab_strings   = self._make_tab('Strings')
        self._tab_imports   = self._make_tab('Imports')
        self._tab_exports   = self._make_tab('Exports')
        self._tab_sections  = self._make_tab('Sections')
        self._tab_resources = self._make_tab('Resources')
        self._tab_anomalies = self._make_tab('Anomalies')

        self._build_overview_tab()
        self._build_strings_tab()
        self._build_imports_tab()
        self._build_exports_tab()
        self._build_sections_tab()
        self._build_resources_tab()
        self._build_anomalies_tab()

    def _make_tab(self, label):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text=f'  {label}  ')
        return frame

    # Overview tab
    def _build_overview_tab(self):
        outer = ttk.Frame(self._tab_overview)
        outer.pack(fill='both', expand=True, padx=12, pady=8)

        # Left column
        left = ttk.Frame(outer)
        left.pack(side='left', fill='both', expand=True, padx=(0, 6))

        self._info_frame = self._labelled_panel(left, 'File Information')
        self._info_vars  = {}

        self._compiler_frame = self._labelled_panel(left, 'Language / Compiler')
        self._compiler_text  = self._scrolled_text(self._compiler_frame, height=6)

        self._packer_frame = self._labelled_panel(left, 'Packers / Protectors')
        self._packer_text  = self._scrolled_text(self._packer_frame, height=4)

        self._args_frame = self._labelled_panel(left, 'Arguments')
        self._args_text  = self._scrolled_text(self._args_frame, height=5)
        self._make_text_context_menu(self._args_text)

        # Right column: version info and signature.
        right = ttk.Frame(outer)
        right.pack(side='right', fill='both', expand=True, padx=(6, 0))

        self._version_frame = self._labelled_panel(right, 'Version Information')
        self._version_text  = self._scrolled_text(self._version_frame, height=10)

        self._sig_frame = self._labelled_panel(right, 'Digital Signature')
        self._sig_label = ttk.Label(self._sig_frame, text='—', foreground=FG_DIM,
                                    background=PANEL_BG, font=UI_FONT)
        self._sig_label.pack(anchor='w', padx=8, pady=4)

    def _labelled_panel(self, parent, title):
        frame = ttk.Frame(parent, style='Panel.TFrame')
        frame.pack(fill='x', pady=(0, 8))
        ttk.Label(frame, text=title, background=PANEL_BG, foreground=ACCENT,
                  font=BOLD_FONT).pack(anchor='w', padx=8, pady=(6, 2))
        sep = ttk.Frame(frame, style='Separator.TFrame', height=1)
        sep.pack(fill='x', padx=8, pady=(0, 4))
        return frame

    def _scrolled_text(self, parent, height=8, mono=True):
        font = MONO_FONT if mono else UI_FONT
        txt = tk.Text(parent, height=height, bg=PANEL_BG, fg=FG,
                      insertbackground=FG, font=font, relief='flat',
                      borderwidth=0, state='disabled', wrap='none')
        sb  = ttk.Scrollbar(parent, orient='vertical', command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y', padx=(0, 4))
        txt.pack(fill='both', expand=True, padx=(8, 0), pady=(0, 6))
        return txt

    # Strings tab
    def _build_strings_tab(self):
        top = ttk.Frame(self._tab_strings)
        top.pack(fill='x', padx=12, pady=(8, 4))

        ttk.Label(top, text='Filter:', style='Dim.TLabel').pack(side='left')
        self._str_filter_var = tk.StringVar()
        self._str_filter_var.trace_add('write', lambda *_: self._apply_string_filter())
        entry = ttk.Entry(top, textvariable=self._str_filter_var, width=30)
        entry.pack(side='left', padx=6)

        ttk.Label(top, text='Category:', style='Dim.TLabel').pack(side='left', padx=(12, 0))
        self._str_cat_var = tk.StringVar(value='All')
        cats = ('All', 'ASCII', 'UTF-16', 'URL', 'Email', 'Path', 'Registry', 'Interesting')
        cat_menu = ttk.Combobox(top, textvariable=self._str_cat_var,
                                values=cats, state='readonly', width=14)
        cat_menu.pack(side='left', padx=6)
        cat_menu.bind('<<ComboboxSelected>>', lambda _: self._apply_string_filter())

        self._str_count_var = tk.StringVar(value='0 strings')
        ttk.Label(top, textvariable=self._str_count_var,
                  style='Dim.TLabel').pack(side='right')
        ttk.Button(top, text='Copy Selected',
                   command=lambda: self._copy_tree_selection(self._str_tree)).pack(side='right', padx=6)

        cols = ('Value', 'Encoding', 'Category')
        self._str_tree = self._make_tree(self._tab_strings, cols,
                                         widths=(600, 80, 100), stretch_col=0)
        self._str_tree.tag_configure('url',         foreground=CYAN)
        self._str_tree.tag_configure('path',        foreground=YELLOW)
        self._str_tree.tag_configure('registry',    foreground='#cba6f7')
        self._str_tree.tag_configure('interesting', foreground=RED)
        self._str_tree.tag_configure('email',       foreground=GREEN)
        self._make_tree_context_menu(self._str_tree)

        self._all_strings = []

    # Imports tab
    def _build_imports_tab(self):
        pane = tk.PanedWindow(self._tab_imports, orient='horizontal',
                              bg=DARK_BG, sashwidth=4, sashrelief='flat')
        pane.pack(fill='both', expand=True, padx=4, pady=4)

        dll_frame = ttk.Frame(pane)
        pane.add(dll_frame, width=260)

        ttk.Label(dll_frame, text='DLLs', style='Header.TLabel').pack(anchor='w', padx=8, pady=4)
        self._dll_tree = self._make_tree(dll_frame, ('DLL', 'Count'),
                                          widths=(180, 50), stretch_col=0)
        self._dll_tree.bind('<<TreeviewSelect>>', self._on_dll_select)

        func_frame = ttk.Frame(pane)
        pane.add(func_frame)

        ttk.Label(func_frame, text='Functions', style='Header.TLabel').pack(anchor='w', padx=8, pady=4)
        self._func_tree = self._make_tree(func_frame, ('Function',), widths=(500,), stretch_col=0)

        self._imports_data = {}

    # Exports tab
    def _build_exports_tab(self):
        ttk.Label(self._tab_exports, text='Exported Functions',
                  style='Header.TLabel').pack(anchor='w', padx=12, pady=(8, 2))
        self._export_tree = self._make_tree(self._tab_exports, ('Function',),
                                             widths=(700,), stretch_col=0)

    # Sections tab
    def _build_sections_tab(self):
        ttk.Label(self._tab_sections, text='PE Sections',
                  style='Header.TLabel').pack(anchor='w', padx=12, pady=(8, 2))
        cols  = ('Name', 'Virt Addr', 'Virt Size', 'Raw Size', 'Entropy', 'Flags', 'MD5')
        widths = (80, 100, 90, 90, 70, 200, 260)
        self._sec_tree = self._make_tree(self._tab_sections, cols,
                                          widths=widths, stretch_col=5)
        self._sec_tree.tag_configure('high_entropy', foreground=RED)
        self._sec_tree.tag_configure('med_entropy',  foreground=YELLOW)

    # Resources tab
    def _build_resources_tab(self):
        ttk.Label(self._tab_resources, text='Embedded Resources',
                  style='Header.TLabel').pack(anchor='w', padx=12, pady=(8, 2))
        cols   = ('Type', 'Count', 'Total Size')
        widths = (180, 70, 120)
        self._res_tree = self._make_tree(self._tab_resources, cols,
                                          widths=widths, stretch_col=0)

    # Anomalies tab
    def _build_anomalies_tab(self):
        ttk.Label(self._tab_anomalies, text='Detected Anomalies',
                  style='Header.TLabel').pack(anchor='w', padx=12, pady=(8, 2))
        self._anom_text = self._scrolled_text(self._tab_anomalies, height=30)

    # Helpers
    def _make_tree(self, parent, columns, widths=None, stretch_col=0):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True, padx=4, pady=(0, 4))

        tree = ttk.Treeview(frame, columns=columns, show='headings',
                             selectmode='extended')
        vsb  = ttk.Scrollbar(frame, orient='vertical',   command=tree.yview)
        hsb  = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side='right',  fill='y')
        hsb.pack(side='bottom', fill='x')
        tree.pack(fill='both', expand=True)

        for i, col in enumerate(columns):
            w       = widths[i] if widths else 120
            stretch = 'yes' if i == stretch_col else 'no'
            tree.heading(col, text=col)
            tree.column(col, width=w, stretch=stretch, anchor='w')
        return tree

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('end', text)
        widget.configure(state='disabled')

    @staticmethod
    def _clear_tree(tree):
        for item in tree.get_children():
            tree.delete(item)

    # File selection
    def _browse(self):
        path = filedialog.askopenfilename(
            title='Select executable',
            filetypes=[('PE files', '*.exe *.dll *.sys *.ocx *.drv *.scr *.cpl *.efi'),
                       ('All files', '*.*')],
        )
        if path:
            self._path_var.set(path)
            self._start_analysis()

    # Analysis
    def _start_analysis(self):
        path = self._path_var.get().strip().strip('"').strip("'")
        if not path:
            messagebox.showwarning('No file', 'Please select a file first.')
            return
        if not os.path.isfile(path):
            messagebox.showerror('File not found', f'Cannot find:\n{path}')
            return

        self._status_var.set(f'Analysing {os.path.basename(path)} …')
        self._progress.start(12)
        threading.Thread(target=self._run_analysis, args=(path,), daemon=True).start()

    def _run_analysis(self, path):
        try:
            results = ExeAnalyzer(path).run_full_analysis()
            self.after(0, self._populate_ui, results)
        except Exception as exc:
            self.after(0, self._on_error, str(exc))

    def _on_error(self, msg):
        self._progress.stop()
        self._status_var.set('Analysis failed.')
        messagebox.showerror('Analysis error', msg)

    # -- Populate UI after analysis completes --

    def _populate_ui(self, results):
        self._results = results
        self._progress.stop()

        fname = results['basic'].get('Filename', 'unknown')
        self._status_var.set(f'Analysis complete — {fname}')

        self._populate_overview(results)
        self._populate_strings(results['strings'])
        self._populate_imports(results['imports'])
        self._populate_exports(results['exports'])
        self._populate_sections(results['sections'])
        self._populate_resources(results['resources'])
        self._populate_anomalies(results['anomalies'])

    def _populate_overview(self, results):
        # Re-populate the File Information panel by destroying all child
        # labels from the previous run and rebuilding them.  The panel
        # frame and its separator are retained.
        for widget in list(self._info_frame.winfo_children()):
            if isinstance(widget, ttk.Frame) and widget.winfo_class() == 'TFrame':
                # preserve separator
                pass

        # Destroy only label widgets, leaving the panel frame and separator.
        for widget in self._info_frame.winfo_children():
            if isinstance(widget, tk.Label) or (
                    isinstance(widget, ttk.Label) and
                    widget.cget('text') not in ('File Information', '')):
                widget.destroy()

        for key, val in results['basic'].items():
            row_frame = ttk.Frame(self._info_frame, style='Panel.TFrame')
            row_frame.pack(fill='x', padx=8, pady=1)
            ttk.Label(row_frame, text=f'{key}:', background=PANEL_BG,
                      foreground=FG_DIM, font=UI_FONT, width=16,
                      anchor='w').pack(side='left')
            ttk.Label(row_frame, text=str(val), background=PANEL_BG,
                      foreground=FG, font=MONO_FONT,
                      anchor='w', wraplength=460).pack(side='left', fill='x', expand=True)

        ttk.Frame(self._info_frame, style='Panel.TFrame', height=4).pack()

        # Compiler
        compiler_lines = results['compiler'] or ['Could not identify language/compiler']
        self._set_text(self._compiler_text, '\n'.join(compiler_lines))

        # Packers
        packer_lines = results['packers'] or ['None detected']
        self._set_text(self._packer_text, '\n'.join(packer_lines))

        # Arguments — CLI flags extracted from the binary's string content.
        arg_lines = results.get('arguments') or ['No arguments detected']
        self._set_text(self._args_text, '\n'.join(arg_lines))

        # Version info
        if results['version']:
            lines = [f'{k}: {v}' for k, v in results['version'].items()]
            self._set_text(self._version_text, '\n'.join(lines))
        else:
            self._set_text(self._version_text, '(No version resource found)')

        # Signature
        if results['signed']:
            self._sig_label.configure(text='Digitally signed', foreground=GREEN)
        else:
            self._sig_label.configure(text='Not signed', foreground=FG_DIM)

    def _populate_strings(self, strings):
        self._all_strings = strings['all']
        self._apply_string_filter()

    def _apply_string_filter(self):
        # Re-populates the strings treeview based on the current filter state.
        # Operates on in-memory self._all_strings — no re-analysis performed.
        self._clear_tree(self._str_tree)
        needle   = self._str_filter_var.get().lower()
        category = self._str_cat_var.get()

        # Map category labels to treeview tag names for colour coding.
        tag_map = {
            'URL': 'url', 'Path': 'path', 'Registry': 'registry',
            'Interesting': 'interesting', 'Email': 'email',
        }

        shown = 0
        for row in self._all_strings:
            val  = row['value']
            enc  = row['encoding']
            cat  = row.get('category', '')

            # Text filter: substring match against the string value.
            if needle and needle not in val.lower():
                continue
            # Category filter: encoding-based (ASCII/UTF-16) or tag-based.
            if category != 'All':
                if category in ('ASCII', 'UTF-16') and enc != category:
                    continue
                if category not in ('ASCII', 'UTF-16') and cat != category:
                    continue

            tag = tag_map.get(cat, '')
            self._str_tree.insert('', 'end', values=(val, enc, cat or '—'),
                                   tags=(tag,) if tag else ())
            shown += 1

        self._str_count_var.set(f'{shown} strings')

    def _populate_imports(self, imports):
        self._clear_tree(self._dll_tree)
        self._clear_tree(self._func_tree)
        self._imports_data = imports
        for dll, funcs in sorted(imports.items(), key=lambda x: -len(x[1])):
            self._dll_tree.insert('', 'end', iid=dll, values=(dll, len(funcs)))

    def _on_dll_select(self, _event=None):
        self._clear_tree(self._func_tree)
        sel = self._dll_tree.selection()
        if not sel:
            return
        dll   = sel[0]
        funcs = self._imports_data.get(dll, [])
        for fn in sorted(funcs):
            self._func_tree.insert('', 'end', values=(fn,))

    def _populate_exports(self, exports):
        self._clear_tree(self._export_tree)
        if not exports:
            self._export_tree.insert('', 'end', values=('(no exports)',))
            return
        for exp in sorted(exports):
            self._export_tree.insert('', 'end', values=(exp,))

    def _populate_sections(self, sections):
        self._clear_tree(self._sec_tree)
        for sec in sections:
            ent  = sec['entropy']
            tag  = 'high_entropy' if ent > 7.0 else ('med_entropy' if ent > 5.5 else '')
            self._sec_tree.insert('', 'end', values=(
                sec['name'],
                sec['virtual_address'],
                f"{sec['virtual_size']:,}",
                f"{sec['raw_size']:,}",
                f"{ent:.2f}",
                sec['flags'],
                sec['md5'],
            ), tags=(tag,) if tag else ())

    def _populate_resources(self, resources):
        self._clear_tree(self._res_tree)
        if not resources:
            self._res_tree.insert('', 'end', values=('(no resources)', '', ''))
            return
        for res in sorted(resources, key=lambda r: r['type']):
            self._res_tree.insert('', 'end', values=(
                res['type'], res['count'], f"{res['size']:,} bytes",
            ))

    def _populate_anomalies(self, anomalies):
        if anomalies:
            self._set_text(self._anom_text,
                           '\n'.join(f'  !  {a}' for a in anomalies))
        else:
            self._set_text(self._anom_text, 'No anomalies detected.')

    # Copy helpers
    def _copy_tree_selection(self, tree, col_index=0):
        selected = tree.selection()
        if not selected:
            return
        values = [tree.item(iid, 'values')[col_index] for iid in selected]
        self.clipboard_clear()
        self.clipboard_append('\n'.join(values))

    def _make_tree_context_menu(self, tree, col_index=0):
        menu = tk.Menu(self, tearoff=0, bg=PANEL_BG, fg=FG,
                       activebackground=ACCENT, activeforeground=DARK_BG, bd=0)
        menu.add_command(label='Copy', command=lambda: self._copy_tree_selection(tree, col_index))
        def _show(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        tree.bind('<Button-3>', _show)
        tree.bind('<Control-c>', lambda _: self._copy_tree_selection(tree, col_index))

    def _make_text_context_menu(self, widget):
        menu = tk.Menu(self, tearoff=0, bg=PANEL_BG, fg=FG,
                       activebackground=ACCENT, activeforeground=DARK_BG, bd=0)
        def _copy_all():
            content = widget.get('1.0', 'end-1c')
            if content:
                self.clipboard_clear()
                self.clipboard_append(content)
        menu.add_command(label='Copy All', command=_copy_all)
        def _show(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        widget.bind('<Button-3>', _show)

# Entry point
def main():
    app = ExeAnalyzerApp()
    # If a file path is passed as a command-line argument, pre-load and analyse it.
    if len(sys.argv) == 2 and os.path.isfile(sys.argv[1]):
        app._path_var.set(sys.argv[1])
        app.after(100, app._start_analysis)
    app.mainloop()

if __name__ == '__main__':
    main()