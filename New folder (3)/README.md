# ANTIGRAVITY UNIVERSAL BINARY DECODER SYSTEM
## Version 3.0 ULTRA - Complete Feature List

### 🎯 Core Capabilities

This is now a **world-class binary analysis system** capable of decoding and analyzing:
- ✅ **Windows EXE files** (PE format)
- ✅ **MetaTrader 4/5 files** (EX4/EX5)
- ✅ **MQL4 & MQL5 code**
- ✅ **C/C++ executables**
- ✅ **C# / .NET applications**
- ✅ **Python executables**
- ✅ **Java bytecode**
- ✅ **Delphi applications**
- ✅ **Visual Basic programs**
- ✅ **Any binary file or hex dump**

---

## 🔬 Advanced Analysis Features

### 1. **PE Header Analysis**
- Parses DOS and PE headers
- Extracts entry points and image base addresses
- Identifies 32-bit vs 64-bit executables
- Maps all PE sections (.text, .data, .rsrc, etc.)

### 2. **Import Table Analysis**
- Lists all imported DLLs
- Identifies system APIs being used
- Detects trading functions (OrderSend, etc.)
- Maps dependencies

### 3. **Resource Directory Parsing**
- Extracts version information
- Reads CompanyName, FileDescription, FileVersion
- Retrieves ProductName and Copyright info
- Identifies original filename

### 4. **Entropy Calculation**
- Shannon entropy analysis
- Packer/encryption detection (>7.0 = packed)
- Compression ratio estimation

### 5. **Multi-Language Detection**
Automatically identifies:
- MQL4/MQL5 (MetaTrader)
- C# / .NET Framework
- Visual Basic 6.0
- Python (CPython)
- Java
- Delphi / C++ Builder
- MSVC++ / GCC

### 6. **x86 Disassembly**
- Basic x86 instruction decoding
- PUSH, POP, MOV, CALL, RET recognition
- Function call mapping
- Hex dump with assembly view

### 7. **Universal Code Reconstruction**
Generates source code templates based on detected language:
- **MQL4**: Complete EA structure with OnTick(), inputs, trading logic
- **MQL5**: Modern MQL5 with CTrade class
- **Python**: Module structure with imports and main()
- **C#**: Namespace, class, and Main() method
- **C++**: Headers, main(), and string tables
- **Generic**: String dump for unknown formats

### 8. **String Extraction**
- ASCII string extraction
- Unicode (UTF-16LE) string extraction
- Offset tracking for all strings
- Minimum length filtering

### 9. **Security Scanning**
Detects:
- UPX packer signatures
- MetaQuotes software markers
- .NET Framework indicators
- Runtime library signatures
- Compiler fingerprints

---

## 📊 Dual Report Generation

### HTML Report
- **Professional dark-themed UI**
- Syntax-highlighted code
- Interactive sections
- Sidebar with quick info
- Color-coded entropy warnings
- Tabular data for sections/imports

### Text Report
- Plain text format
- Easy to share/log
- Complete analysis dump
- All findings in readable format

---

## 🚀 Usage

### Analyze an EXE file:
```bash
python main.py
# Then provide the path to your .exe file
```

### Analyze a raw dump:
1. Paste your hex/binary dump into `input.txt`
2. Run `python main.py`

### Quick run:
```bash
run_decoder.bat
```

---

## 📁 Output Files

For each analysis, you get:
- `Analysis_Report_[filename].html` - Interactive HTML report
- `Analysis_Report_[filename].txt` - Plain text report

Both reports contain:
- File information & entropy
- Detected programming language
- Version info (if PE file)
- PE headers & sections
- Imported libraries
- Security signatures
- Reconstructed source code
- Disassembly view
- String table

---

## 🎨 Key Features

✨ **No External Dependencies** - Pure Python implementation
✨ **Self-Contained** - Manual PE parsing, no pefile library needed
✨ **Multi-Format** - Handles EXE, EX4, EX5, and raw dumps
✨ **Smart Detection** - Automatic language identification
✨ **Professional Reports** - Beautiful HTML + clean text output
✨ **Deep Analysis** - From headers to reconstructed code

---

## 🔧 Technical Details

- **Language**: Python 3.x
- **Libraries**: Built-in only (struct, re, math, html)
- **PE Parsing**: Manual implementation
- **Disassembler**: Custom x86 decoder
- **Code Reconstruction**: Heuristic-based analysis

---

## 🎯 Perfect For

- Reverse engineering
- Malware analysis
- Software auditing
- MQL4/MQL5 decompilation
- Binary forensics
- Code recovery
- Security research

---

**ANTIGRAVITY UNIVERSAL DECODER v3.0 ULTRA**
*The most powerful binary analysis system for EXE and MQL files*
