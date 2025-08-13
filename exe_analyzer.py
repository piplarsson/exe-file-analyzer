import pefile
import sys
import os
import re
import hashlib
from datetime import datetime
import struct

class ExeAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.file_content = None
        self.signatures = {
            # Compilers and languages
            'Visual C++': [
                b'Microsoft Visual C++',
                b'MSVCRT',
                b'_CRT_INIT',
                b'__CxxFrameHandler',
                b'Visual Studio'
            ],
            'Visual Basic': [
                b'VB5!',
                b'VB6',
                b'MSVBVM60.DLL',
                b'__vbaStrCmp',
                b'__vbaVarTstEq'
            ],
            'Delphi': [
                b'Borland',
                b'Delphi',
                b'TForm',
                b'TApplication',
                b'System@@LStrCmp',
                b'FastMM'
            ],
            '.NET/C#': [
                b'mscoree.dll',
                b'_CorExeMain',
                b'mscorlib',
                b'.NETFramework',
                b'System.Runtime',
                b'CLR Header'
            ],
            'Python': [
                b'python',
                b'PyInstaller',
                b'pyi-windows-manifest-filename',
                b'Py_Initialize',
                b'PyEval_',
                b'py2exe'
            ],
            'Go': [
                b'Go build ID:',
                b'runtime.gopanic',
                b'runtime.main',
                b'go.buildid',
                b'golang.org'
            ],
            'Rust': [
                b'rust_panic',
                b'rust_begin_unwind',
                b'.rs',
                b'cargo',
                b'rustc'
            ],
            'MinGW/GCC': [
                b'mingw',
                b'__mingw',
                b'libgcc',
                b'__gcc',
                b'GNU C'
            ],
            'AutoIt': [
                b'AutoIt v3',
                b'AU3!',
                b'AutoIt3ExecuteLine',
                b'AutoItSC'
            ],
            'NSIS Installer': [
                b'Nullsoft',
                b'NSIS',
                b'nsis.sf.net',
                b'NSIS.Library'
            ],
            'UPX Packed': [
                b'UPX!',
                b'UPX0',
                b'UPX1',
                b'UPX2',
                b'UPX3'
            ],
            'Java/JAR': [
                b'java',
                b'jar',
                b'JVM',
                b'javaw.exe'
            ],
            'Electron/Node.js': [
                b'Electron',
                b'node.dll',
                b'v8',
                b'chromium'
            ],
            'Qt Framework': [
                b'Qt5Core',
                b'Qt6Core',
                b'QtCore4',
                b'qwindows'
            ]
        }
        
        # Packers and protectors
        self.packers = {
            'UPX': [b'UPX!', b'UPX0', b'UPX1'],
            'ASPack': [b'ASPack', b'.aspack'],
            'PECompact': [b'PECompact', b'PEC2'],
            'Themida': [b'Themida', b'.themida'],
            'VMProtect': [b'.vmp0', b'.vmp1', b'VMProtect'],
            'Enigma': [b'Enigma', b'enigma1'],
            'MPRESS': [b'MPRESS', b'.MPRESS'],
            'Petite': [b'petite', b'.petite'],
            'FSG': [b'FSG!', b'FSG v'],
            'MEW': [b'MEW', b'MEW11']
        }
    
    def load_file(self):
        """Load PE file"""
        try:
            self.pe = pefile.PE(self.filepath)
            with open(self.filepath, 'rb') as f:
                self.file_content = f.read()
            return True
        except Exception as e:
            print(f"Error loading file: {e}")
            return False
    
    def get_basic_info(self):
        """Get basic information about the file"""
        info = {}
        info['Filename'] = os.path.basename(self.filepath)
        info['File Size'] = f"{os.path.getsize(self.filepath):,} bytes"
        
        # Calculate hash values
        info['MD5'] = hashlib.md5(self.file_content).hexdigest()
        info['SHA1'] = hashlib.sha1(self.file_content).hexdigest()
        info['SHA256'] = hashlib.sha256(self.file_content).hexdigest()[:32] + "..."
        
        if self.pe:
            # Compile time
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
            dt = datetime.fromtimestamp(timestamp)
            info['Compiled'] = dt.strftime('%Y-%m-%d %H:%M:%S')
            
            # Architecture
            if self.pe.FILE_HEADER.Machine == 0x14c:
                info['Architecture'] = '32-bit (x86)'
            elif self.pe.FILE_HEADER.Machine == 0x8664:
                info['Architecture'] = '64-bit (x64)'
            elif self.pe.FILE_HEADER.Machine == 0x1c0:
                info['Architecture'] = 'ARM'
            elif self.pe.FILE_HEADER.Machine == 0xaa64:
                info['Architecture'] = 'ARM64'
            else:
                info['Architecture'] = f'Unknown (0x{self.pe.FILE_HEADER.Machine:04x})'
            
            # Subsystem
            subsystem_types = {
                1: 'Native',
                2: 'Windows GUI',
                3: 'Windows Console',
                5: 'OS/2 Console',
                7: 'POSIX Console',
                9: 'Windows CE GUI',
                10: 'EFI Application',
                11: 'EFI Boot Service Driver',
                12: 'EFI Runtime Driver',
                13: 'EFI ROM',
                14: 'Xbox',
                16: 'Windows Boot Application'
            }
            subsystem = self.pe.OPTIONAL_HEADER.Subsystem
            info['Subsystem'] = subsystem_types.get(subsystem, f'Unknown ({subsystem})')
            
            # Entry point
            info['Entry Point'] = f"0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}"
            
            # Image base
            info['Image Base'] = f"0x{self.pe.OPTIONAL_HEADER.ImageBase:08x}"
            
            # Linker version
            info['Linker Version'] = f"{self.pe.OPTIONAL_HEADER.MajorLinkerVersion}.{self.pe.OPTIONAL_HEADER.MinorLinkerVersion}"
            
            # OS Version
            info['OS Version'] = f"{self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}"
            
            # Number of sections
            info['Sections Count'] = self.pe.FILE_HEADER.NumberOfSections
        
        return info
    
    def get_sections_info(self):
        """Get information about sections"""
        sections = []
        if not self.pe:
            return sections
        
        for section in self.pe.sections:
            sec_info = {
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
                'md5': section.get_hash_md5(),
                'characteristics': []
            }
            
            # Analyze characteristics
            characteristics = section.Characteristics
            if characteristics & 0x20:
                sec_info['characteristics'].append('CODE')
            if characteristics & 0x40:
                sec_info['characteristics'].append('DATA')
            if characteristics & 0x80:
                sec_info['characteristics'].append('UNINITIALIZED_DATA')
            if characteristics & 0x20000000:
                sec_info['characteristics'].append('EXECUTABLE')
            if characteristics & 0x40000000:
                sec_info['characteristics'].append('READABLE')
            if characteristics & 0x80000000:
                sec_info['characteristics'].append('WRITABLE')
            
            sections.append(sec_info)
        
        return sections
    
    def detect_packer(self):
        """Detect if file is packed"""
        detected_packers = []
        
        if not self.file_content:
            return detected_packers
        
        # Search for packer signatures
        for packer, signatures in self.packers.items():
            for sig in signatures:
                if sig.lower() in self.file_content.lower():
                    if packer not in detected_packers:
                        detected_packers.append(packer)
                    break
        
        # Check entropy (high entropy may indicate packing)
        if self.pe:
            high_entropy_sections = 0
            for section in self.pe.sections:
                if section.get_entropy() > 7.0:
                    high_entropy_sections += 1
            
            if high_entropy_sections >= len(self.pe.sections) * 0.5:
                detected_packers.append("Possible unknown packer (high entropy)")
        
        return detected_packers
    
    def get_version_info(self):
        """Get version information"""
        version_info = {}
        
        if not hasattr(self.pe, 'VS_VERSIONINFO'):
            return version_info
        
        if hasattr(self.pe, 'FileInfo'):
            for fileinfo in self.pe.FileInfo:
                if hasattr(fileinfo, 'StringTable'):
                    for st in fileinfo.StringTable:
                        for entry in st.entries.items():
                            key = entry[0].decode('utf-8', errors='ignore')
                            value = entry[1].decode('utf-8', errors='ignore')
                            version_info[key] = value
        
        return version_info
    
    def get_certificates(self):
        """Get certificate information"""
        cert_info = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
            return cert_info
        
        # Here you could parse certificates in more detail
        cert_info.append("Digitally signed file detected")
        
        return cert_info
    
    def get_exports(self):
        """List exported functions"""
        exports = []
        
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8', errors='ignore'))
        
        return exports
    
    def get_resources(self):
        """Analyze resources"""
        resources = {
            'types': {},
            'total_size': 0
        }
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources
        
        def get_resource_type_name(type_id):
            resource_types = {
                1: 'CURSOR',
                2: 'BITMAP',
                3: 'ICON',
                4: 'MENU',
                5: 'DIALOG',
                6: 'STRING',
                7: 'FONTDIR',
                8: 'FONT',
                9: 'ACCELERATOR',
                10: 'RCDATA',
                11: 'MESSAGETABLE',
                12: 'GROUP_CURSOR',
                14: 'GROUP_ICON',
                16: 'VERSION',
                17: 'DLGINCLUDE',
                19: 'PLUGPLAY',
                20: 'VXD',
                21: 'ANICURSOR',
                22: 'ANIICON',
                23: 'HTML',
                24: 'MANIFEST'
            }
            return resource_types.get(type_id, f'TYPE_{type_id}')
        
        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'id'):
                type_name = get_resource_type_name(resource_type.id)
                if type_name not in resources['types']:
                    resources['types'][type_name] = 0
                
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, 'data'):
                                    resources['types'][type_name] += 1
                                    resources['total_size'] += resource_lang.data.struct.Size
        
        return resources
    
    def detect_compiler(self):
        """Attempt to identify compiler/language with more precision"""
        detected = []
        confidence = {}  # Keep track of confidence
        
        if not self.pe or not self.file_content:
            return detected
        
        # Search for signatures with weighting
        for lang, patterns in self.signatures.items():
            matches = 0
            for pattern in patterns:
                if pattern.lower() in self.file_content.lower():
                    matches += 1
            
            if matches > 0:
                confidence[lang] = matches
        
        # Check imported DLLs for more precision
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                
                # Visual C++ runtime versions
                if 'msvcr' in dll_name or 'msvcp' in dll_name:
                    version = re.search(r'(\d+)', dll_name)
                    if version:
                        vc_version = {
                            '140': 'Visual C++ 2015-2022',
                            '120': 'Visual C++ 2013',
                            '110': 'Visual C++ 2012',
                            '100': 'Visual C++ 2010',
                            '90': 'Visual C++ 2008',
                            '80': 'Visual C++ 2005',
                            '71': 'Visual C++ 2003',
                            '70': 'Visual C++ 2002',
                            '60': 'Visual C++ 6.0'
                        }.get(version.group(1), f'Visual C++ (version {version.group(1)})')
                        
                        if vc_version not in detected:
                            detected.append(vc_version)
                
                # .NET versions
                elif 'mscoree' in dll_name:
                    if '.NET/C#' not in detected:
                        # Try to find .NET version
                        clr_version = self.get_clr_version()
                        if clr_version:
                            detected.append(f'.NET/C# ({clr_version})')
                        else:
                            detected.append('.NET/C#')
        
        # Add from confidence dict
        sorted_confidence = sorted(confidence.items(), key=lambda x: x[1], reverse=True)
        for lang, score in sorted_confidence:
            if score >= 2 and lang not in [d.split(' ')[0] for d in detected]:
                detected.append(f"{lang} (confidence: {'high' if score >= 3 else 'medium'})")
        
        return detected
    
    def get_clr_version(self):
        """Try to find CLR version for .NET"""
        if not self.pe:
            return None
        
        # Look for CLR metadata
        clr_patterns = {
            b'v4.0.30319': '.NET Framework 4.x',
            b'v2.0.50727': '.NET Framework 2.0/3.x',
            b'v1.1.4322': '.NET Framework 1.1',
            b'v1.0.3705': '.NET Framework 1.0'
        }
        
        for pattern, version in clr_patterns.items():
            if pattern in self.file_content:
                return version
        
        return None
    
    def get_imports(self):
        """List imported functions and DLLs with more details"""
        imports = {}
        
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            functions = []
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    functions.append(func_name)
                else:
                    functions.append(f"Ordinal: {imp.ordinal}")
            
            imports[dll_name] = {
                'count': len(functions),
                'functions': functions
            }
        
        return imports
    
    def get_strings(self, min_length=6):
        """Extract readable strings from file"""
        strings = {
            'ascii': [],
            'unicode': [],
            'urls': [],
            'emails': [],
            'paths': [],
            'registry': [],
            'interesting': []
        }
        
        if not self.file_content:
            return strings
        
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        ascii_strings = re.findall(ascii_pattern, self.file_content)
        
        # Unicode strings
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        unicode_strings = re.findall(unicode_pattern, self.file_content)
        
        # Process ASCII strings
        for s in ascii_strings[:200]:  # Extended to 200
            decoded = s.decode('ascii', errors='ignore')
            if decoded and not decoded.isspace():
                strings['ascii'].append(decoded)
                
                # Categorize strings
                if re.match(r'https?://', decoded) or re.match(r'ftp://', decoded):
                    strings['urls'].append(decoded)
                elif '@' in decoded and '.' in decoded:
                    strings['emails'].append(decoded)
                elif '\\' in decoded or '/' in decoded:
                    strings['paths'].append(decoded)
                elif 'HKEY_' in decoded or 'Software\\' in decoded:
                    strings['registry'].append(decoded)
                
                # Interesting keywords
                interesting_keywords = [
                    'password', 'secret', 'key', 'token', 'api',
                    'debug', 'error', 'warning', 'version',
                    'copyright', 'license', 'serial'
                ]
                
                for keyword in interesting_keywords:
                    if keyword.lower() in decoded.lower():
                        strings['interesting'].append(decoded)
                        break
        
        # Process Unicode strings
        for s in unicode_strings[:100]:
            try:
                decoded = s.decode('utf-16le', errors='ignore')
                if decoded and not decoded.isspace():
                    strings['unicode'].append(decoded)
            except:
                pass
        
        return strings
    
    def analyze_anomalies(self):
        """Analyze potential anomalies or suspicious properties"""
        anomalies = []
        
        if not self.pe:
            return anomalies
        
        # Check timestamp
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        if timestamp == 0:
            anomalies.append("Timestamp is 0 (possible manipulation)")
        elif timestamp > 2147483647:  # After 2038
            anomalies.append("Suspicious timestamp (future date)")
        
        # Check sections
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            
            # Unusual section names
            if len(section_name) == 0:
                anomalies.append("Empty section name detected")
            elif not section_name.startswith('.'):
                anomalies.append(f"Unusual section name: {section_name}")
            
            # Check sizes
            if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                anomalies.append(f"Section {section_name} has 0 raw size but virtual size > 0")
            
            # Very high entropy
            if section.get_entropy() > 7.5:
                anomalies.append(f"Very high entropy in {section_name}: {section.get_entropy():.2f}")
        
        # Check imports
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            anomalies.append("No imports (unusual for most programs)")
        
        # Check entry point
        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        
        for section in self.pe.sections:
            if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                ep_section = section
                break
        
        if ep_section:
            section_name = ep_section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if section_name not in ['.text', '.code', 'CODE', 'UPX0', 'UPX1']:
                anomalies.append(f"Entry point in unusual section: {section_name}")
        
        return anomalies
    
    def analyze(self):
        """Run complete analysis"""
        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║                   📊 ANALYSIS RESULTS 📊                 ║")
        print("╚══════════════════════════════════════════════════════════╝")
        
        if not self.load_file():
            print("Could not load file!")
            return
        
        # Basic info
        print("\n┌─ BASIC INFORMATION ──────────────────────────────────────┐")
        basic_info = self.get_basic_info()
        for key, value in basic_info.items():
            # Convert value to string to ensure len() works
            value_str = str(value)
            if len(value_str) > 39:
                print(f"│ {key:15} : {value_str[:36]}...│")
            else:
                print(f"│ {key:15} : {value_str:39}│")
        print("└──────────────────────────────────────────────────────────┘")
        
        # Version information
        version_info = self.get_version_info()
        if version_info:
            print("\n┌─ VERSION INFORMATION ──────────────────────────────────┐")
            for key, value in list(version_info.items())[:8]:
                value_str = str(value)  # Convert to string
                key_str = str(key)[:15]
                if len(value_str) > 39:
                    print(f"│ {key_str:15} : {value_str[:36]}...│")
                else:
                    print(f"│ {key_str:15} : {value_str:39}│")
            print("└──────────────────────────────────────────────────────────┘")
        
        # Detect packer
        packers = self.detect_packer()
        if packers:
            print("\n┌─ PACKER/PROTECTOR ───────────────────────────────────────┐")
            for packer in packers:
                print(f"│ ⚠️  {packer:53}│")
            print("└──────────────────────────────────────────────────────────┘")
        
        # Detect compiler/language
        print("\n┌─ DETECTED LANGUAGE/COMPILER ─────────────────────────────┐")
        detected = self.detect_compiler()
        if detected:
            for item in detected:
                print(f"│ ✅ {item:53} │")
        else:
            print("│ ❌ Could not identify language/compiler                 │")
        print("└──────────────────────────────────────────────────────────┘")
        
        # Sections
        print("\n┌─ SECTIONS ───────────────────────────────────────────────┐")
        sections = self.get_sections_info()
        for section in sections[:8]:
            print(f"│ 📁 {section['name']:8} Entropy: {section['entropy']:.2f} "
                  f"Size: {section['raw_size']:>8} bytes           │")
            if section['characteristics']:
                chars = ', '.join(section['characteristics'][:3])
                print(f"│    └─ {chars:49}  │")
        print("└──────────────────────────────────────────────────────────┘")
        
        # Resources
        resources = self.get_resources()
        if resources['types']:
            print("\n┌─ RESOURCES ──────────────────────────────────────────────┐")
            for res_type, count in list(resources['types'].items())[:6]:
                print(f"│ 📦 {res_type:20} : {count:3} items                      │")
            print(f"│ Total size: {resources['total_size']:,} bytes                                  │")
            print("└──────────────────────────────────────────────────────────┘")
        
        # Imported DLLs
        print("\n┌─ IMPORTED DLLs ──────────────────────────────────────────┐")
        imports = self.get_imports()
        if imports:
            sorted_imports = sorted(imports.items(), key=lambda x: x[1]['count'], reverse=True)
            for dll, info in sorted_imports[:8]:
                print(f"│ 📚 {dll:35} ({info['count']:3} functions)   │")
                for func in info['functions'][:3]:
                    if len(func) > 47:
                        print(f"│    └─ {func[:44]}... │")
                    else:
                        print(f"│    └─ {func:49}  │")
        else:
            print("│ No imports found                                         │")
        print("└──────────────────────────────────────────────────────────┘")
        
        # Exported functions
        exports = self.get_exports()
        if exports:
            print("\n┌─ EXPORTED FUNCTIONS ───────────────────────────────────┐")
            for exp in exports[:10]:
                if len(exp) > 53:
                    print(f"│ 📤 {exp[:50]}... │")
                else:
                    print(f"│ 📤 {exp:53} │")
            if len(exports) > 10:
                print(f"│    ... and {len(exports)-10} more functions                           │")
            print("└──────────────────────────────────────────────────────────┘")
        
        # Strings
        print("\n┌─ INTERESTING STRINGS ────────────────────────────────────┐")
        strings = self.get_strings()
        
        # Show URLs
        if strings['urls']:
            print("│ 🌐 URLs:                                                 │")
            for url in strings['urls'][:3]:
                if len(url) > 50:
                    print(f"│    {url[:47]}... │")
                else:
                    print(f"│    {url:53} │")
        
        # Show paths
        if strings['paths']:
            print("│ 📁 Paths:                                                │")
            for path in strings['paths'][:3]:
                if len(path) > 50:
                    print(f"│    {path[:47]}... │")
                else:
                    print(f"│    {path:53} │")
        
        # Show registry
        if strings['registry']:
            print("│ 🔑 Registry:                                             │")
            for reg in strings['registry'][:3]:
                if len(reg) > 50:
                    print(f"│    {reg[:47]}... │")
                else:
                    print(f"│    {reg:53} │")
        
        # Show interesting
        if strings['interesting']:
            print("│ ⚡ Interesting keywords:                                 │")
            for s in strings['interesting'][:5]:
                if len(s) > 50:
                    print(f"│    {s[:47]}... │")
                else:
                    print(f"│    {s:53} │")
        
        print("└──────────────────────────────────────────────────────────┘")
        
        # Anomalies
        anomalies = self.analyze_anomalies()
        if anomalies:
            print("\n┌─ POTENTIAL ANOMALIES ────────────────────────────────────┐")
            for anomaly in anomalies:
                print(f"│ ⚠️  {anomaly:52} │")
            print("└──────────────────────────────────────────────────────────┘")
        
        # Certificate
        certs = self.get_certificates()
        if certs:
            print("\n┌─ DIGITAL SIGNATURE ─────────────────────────────────────┐")
            for cert in certs:
                print(f"│ 🔐 {cert:53} │")
            print("└──────────────────────────────────────────────────────────┘")
        
        # Summary
        print("\n┌─ SUMMARY ────────────────────────────────────────────────┐")
        print(f"│ 📊 Complete analysis done                                │")
        print(f"│ 📁 {len(sections)} sections analyzed                                   │")
        print(f"│ 📚 {len(imports)} DLL files imported                                  │")
        print(f"│ 💬 {len(strings['ascii']) + len(strings['unicode'])} strings extracted                                 │")
        if anomalies:
            print(f"│ ⚠️  {len(anomalies)} anomalies detected                                 │")
        print("└──────────────────────────────────────────────────────────┘")
        
        print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

def main():    
    print("╔══════════════════════════════════════════════════════════╗")
    print("║              🔍 EXE FILE ANALYZER - v1.0 🔍              ║")
    print("║                                                          ║")
    print("║               Language & Compiler Detector               ║")
    print("║                    EXTENDED VERSION                      ║")
    print("║                                                          ║")
    print("║                 Created By Piplarsson_swe                ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print("┌──────────────────────────────────────────────────────────┐")
    print("│ ℹ️  DESCRIPTION:                                         │")
    print("│                                                          │")
    print("│ This program performs in-depth analysis of EXE files:    │")
    print("│  • Detects programming language and compiler             │")
    print("│  • Shows hash values (MD5, SHA1, SHA256)                 │")
    print("│  • Analyzes sections and their entropy                   │")
    print("│  • Identifies packers and protectors                     │")
    print("│  • Extracts version information                          │")
    print("│  • Lists imported and exported functions                 │")
    print("│  • Analyzes resources                                    │")
    print("│  • Finds URLs, paths and registry keys                   │")
    print("│  • Detects potential anomalies                           │")
    print("│  • Checks digital signature                              │")
    print("│                                                          │")
    print("│ Supports: C++, C#/.NET, Python, Go, Rust, Delphi etc.    │")
    print("└──────────────────────────────────────────────────────────┘")
    print()
    
    # Check if path was given as argument
    if len(sys.argv) == 2:
        filepath = sys.argv[1]
        print(f"📂 Using file from command line: {filepath}")
        print()
    else:
        # Ask user for path
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        filepath = input("🔍 Enter path to EXE file: ").strip()
        
        # Remove any quotation marks
        filepath = filepath.strip('"').strip("'")
    
    if not filepath:
        print("\n❌ Error: No path specified!")
        input("\n📌 Press Enter to exit...")
        sys.exit(1)
    
    if not os.path.exists(filepath):
        print(f"\n❌ Error: File '{filepath}' not found!")
        print("💡 Tip: Check that the path is correct.")
        input("\n📌 Press Enter to exit...")
        sys.exit(1)
    
    if not filepath.lower().endswith('.exe'):
        print("\n⚠️  Warning: File doesn't appear to be an .exe file")
        answer = input("Do you want to continue anyway? (y/n): ").lower()
        if answer != 'y':
            print("🚫 Aborting...")
            sys.exit(0)
    
    print("\n🔄 Analyzing file...")
    print("⏳ This may take a few seconds...")
    
    try:
        analyzer = ExeAnalyzer(filepath)
        analyzer.analyze()
    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        import traceback
        print("\n📋 Detailed error information:")
        traceback.print_exc()
    
    print("\n✅ Analysis complete!")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    input("\n📌 Press Enter to exit...")

if __name__ == "__main__":
    main()