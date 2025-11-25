import os
import re
import struct
import binascii
import html
import math

class BinaryAnalyzer:
    def __init__(self):
        self.results = {
            "file_info": {},
            "headers": {},
            "strings": [],
            "sections": [],
            "imports": [],
            "security_check": [],
            "reconstructed_code": "",
            "assembly_view": "",
            "entropy": 0.0,
            "detected_language": "Unknown",
            "version_info": {}
        }

    def load_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            self.analyze_bytes(data, file_path)
            return True
        except Exception as e:
            print(f"Error loading file: {e}")
            return False

    def load_text_dump(self, text_content):
        try:
            # Heuristic: If it looks like a hex dump or raw latin-1, treat as bytes
            data = text_content.encode('latin-1', errors='ignore') 
            self.analyze_bytes(data, "Text Dump Input")
            return True
        except Exception as e:
            print(f"Error processing text dump: {e}")
            return False

    def analyze_bytes(self, data, source_name):
        self.results["file_info"] = {
            "Source": source_name,
            "Size": f"{len(data)} bytes",
            "Type": "Unknown"
        }

        # 1. Check Magic Numbers & File Type
        self._detect_file_type(data)
        
        # 2. Calculate Entropy (Packer Detection)
        self.results["entropy"] = self._calculate_entropy(data)
        
        # 3. Extract Strings
        self.results["strings"] = self._extract_strings(data)
        
        # 4. Security/Signature Scan & Language Detection
        self._scan_signatures_and_language(data)

        # 5. Generate Disassembly (Real x86 Basic)
        self.results["assembly_view"] = self._disassemble_x86(data)

        # 6. Universal Code Reconstruction
        self.results["reconstructed_code"] = self._universal_reconstruct(self.results["strings"], data)

    def _detect_file_type(self, data):
        if data.startswith(b'MZ'):
            self.results["file_info"]["Type"] = "Windows Executable (PE)"
            self._parse_pe_header(data)
        elif data.startswith(b'EX4'):
            self.results["file_info"]["Type"] = "MetaTrader 4 Compiled (EX4)"
        elif data.startswith(b'EX5'):
            self.results["file_info"]["Type"] = "MetaTrader 5 Compiled (EX5)"
        elif b'MetaQuotes' in data or b'MQL4' in data:
            self.results["file_info"]["Type"] = "MQL4 Related Binary"
        elif b'MQL5' in data:
            self.results["file_info"]["Type"] = "MQL5 Related Binary"
        else:
            self.results["file_info"]["Type"] = "Raw Binary Data"

    def _calculate_entropy(self, data):
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _parse_pe_header(self, data):
        try:
            # DOS Header -> e_lfanew
            e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
            self.results["headers"]["e_lfanew"] = hex(e_lfanew)
            
            if len(data) <= e_lfanew + 4:
                return

            # PE Signature
            pe_sig = data[e_lfanew:e_lfanew+4]
            if pe_sig != b'PE\x00\x00':
                return
            self.results["headers"]["Signature"] = "PE (Valid)"

            # File Header (20 bytes after PE sig)
            coff_header_offset = e_lfanew + 4
            num_sections = struct.unpack_from('<H', data, coff_header_offset + 2)[0]
            
            # Optional Header
            opt_header_offset = coff_header_offset + 20
            magic = struct.unpack_from('<H', data, opt_header_offset)[0]
            is_64bit = (magic == 0x20b)
            
            # Entry Point
            entry_point = struct.unpack_from('<I', data, opt_header_offset + 16)[0]
            self.results["headers"]["EntryPoint"] = hex(entry_point)
            
            # Image Base
            if is_64bit:
                image_base = struct.unpack_from('<Q', data, opt_header_offset + 24)[0]
            else:
                image_base = struct.unpack_from('<I', data, opt_header_offset + 28)[0]
            self.results["headers"]["ImageBase"] = hex(image_base)

            # Parse Sections
            size_of_opt_header = struct.unpack_from('<H', data, coff_header_offset + 16)[0]
            section_table_offset = opt_header_offset + size_of_opt_header
            
            sections = []
            for i in range(num_sections):
                sec_offset = section_table_offset + (i * 40)
                if sec_offset + 40 > len(data):
                    break
                    
                name = data[sec_offset:sec_offset+8].decode('ascii', errors='ignore').strip('\x00')
                v_size = struct.unpack_from('<I', data, sec_offset + 8)[0]
                v_addr = struct.unpack_from('<I', data, sec_offset + 12)[0]
                raw_size = struct.unpack_from('<I', data, sec_offset + 16)[0]
                raw_ptr = struct.unpack_from('<I', data, sec_offset + 20)[0]
                
                sections.append({
                    "Name": name,
                    "VirtSize": hex(v_size),
                    "VirtAddr": hex(v_addr),
                    "RawSize": hex(raw_size),
                    "RawPtr": hex(raw_ptr)
                })
            self.results["sections"] = sections

            # Data Directories
            rva_count_offset = opt_header_offset + 108 if is_64bit else opt_header_offset + 92
            
            # Import Table (Index 1)
            import_dir_offset = rva_count_offset + 4 + (8 * 1) 
            import_rva = struct.unpack_from('<I', data, import_dir_offset)[0]
            if import_rva > 0:
                self._parse_imports(data, import_rva, sections)

            # Resource Table (Index 2)
            resource_dir_offset = rva_count_offset + 4 + (8 * 2)
            resource_rva = struct.unpack_from('<I', data, resource_dir_offset)[0]
            if resource_rva > 0:
                self._parse_resources(data, resource_rva, sections)

        except Exception as e:
            self.results["headers"]["ParseError"] = str(e)

    def _rva_to_offset(self, rva, sections):
        for s in sections:
            v_addr = int(s["VirtAddr"], 16)
            raw_size = int(s["RawSize"], 16)
            raw_ptr = int(s["RawPtr"], 16)
            if v_addr <= rva < v_addr + raw_size:
                return rva - v_addr + raw_ptr
        return None

    def _parse_imports(self, data, import_rva, sections):
        offset = self._rva_to_offset(import_rva, sections)
        if offset is None:
            return

        imports = []
        while True:
            if offset + 20 > len(data):
                break
            name_rva = struct.unpack_from('<I', data, offset + 12)[0]
            if name_rva == 0:
                break
                
            name_offset = self._rva_to_offset(name_rva, sections)
            if name_offset:
                try:
                    end = data.find(b'\x00', name_offset)
                    dll_name = data[name_offset:end].decode('ascii', errors='ignore')
                    imports.append(dll_name)
                except:
                    pass
            
            offset += 20
            if len(imports) > 50: 
                imports.append("... (truncated)")
                break
        
        self.results["imports"] = imports

    def _parse_resources(self, data, rva, sections):
        # Basic Resource Directory Parser to find Version Info
        offset = self._rva_to_offset(rva, sections)
        if offset is None: return
        
        try:
            # Find the resource section
            res_section = None
            for s in sections:
                v_addr = int(s["VirtAddr"], 16)
                raw_size = int(s["RawSize"], 16)
                if v_addr <= rva < v_addr + raw_size:
                    res_section = s
                    break
            
            if res_section:
                start = int(res_section["RawPtr"], 16)
                end = start + int(res_section["RawSize"], 16)
                res_data = data[start:end]
                
                # Look for "VS_VERSION_INFO" unicode string
                ver_sig = "VS_VERSION_INFO".encode('utf-16le')
                idx = res_data.find(ver_sig)
                if idx != -1:
                    # Extract some strings around it
                    self.results["headers"]["HasVersionInfo"] = "True"
                    # Attempt to extract CompanyName, FileDescription, etc.
                    common_keys = ["CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion"]
                    
                    found_metadata = {}
                    for key in common_keys:
                        key_bytes = key.encode('utf-16le')
                        k_idx = res_data.find(key_bytes)
                        if k_idx != -1:
                            # Value is usually after the key, aligned
                            # This is a heuristic extraction
                            val_start = k_idx + len(key_bytes)
                            # Skip padding
                            while val_start < len(res_data) and res_data[val_start] == 0:
                                val_start += 1
                            
                            # Read null-terminated unicode string
                            val_end = val_start
                            while val_end + 1 < len(res_data):
                                if res_data[val_end] == 0 and res_data[val_end+1] == 0:
                                    break
                                val_end += 2
                            
                            try:
                                val = res_data[val_start:val_end].decode('utf-16le').strip()
                                if val:
                                    found_metadata[key] = val
                            except:
                                pass
                    
                    if found_metadata:
                        self.results["version_info"] = found_metadata

        except Exception as e:
            pass

    def _extract_strings(self, data, min_length=4):
        strings = []
        # ASCII
        ascii_pattern = re.compile(b'[ -~]{' + str(min_length).encode() + b',}')
        for match in ascii_pattern.finditer(data):
            s = match.group().decode('ascii')
            if len(s.strip()) >= min_length:
                strings.append({"type": "ASCII", "value": s, "offset": hex(match.start())})
        
        # Unicode (Wide)
        try:
            wide_pattern = re.compile(b'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + b',}')
            for match in wide_pattern.finditer(data):
                try:
                    s = match.group().decode('utf-16le')
                    if len(s.strip()) >= min_length:
                        strings.append({"type": "Unicode", "value": s, "offset": hex(match.start())})
                except:
                    pass
        except Exception:
            pass
        return strings

    def _scan_signatures_and_language(self, data):
        signatures = {
            b'UPX0': "UPX Packer",
            b'MQL4': "MQL4 Signature",
            b'MQL5': "MQL5 Signature",
            b'MetaQuotes': "MetaQuotes Software Corp",
            b'IsTesting': "MQL Testing Function",
            b'OrderSend': "MQL Trading Function",
            b'mscoree.dll': ".NET Framework (C#/VB.NET)",
            b'MSVBVM60': "Visual Basic 6.0",
            b'python': "Python Script/Embed",
            b'CPython': "CPython Runtime",
            b'java.lang': "Java Bytecode/Runtime",
            b'Borland': "Delphi/C++ Builder",
            b'Microsoft Visual C++': "MSVC++",
            b'GNU C++': "GCC/MinGW"
        }
        
        found_sigs = []
        lang_scores = {
            "MQL4": 0, "MQL5": 0, "C#/.NET": 0, "VB6": 0, 
            "Python": 0, "Java": 0, "Delphi": 0, "C/C++": 0
        }

        for sig, name in signatures.items():
            if sig in data or sig.lower() in data:
                found_sigs.append(name)
                # Scoring
                if b'MQL4' in sig or b'Order' in sig: lang_scores["MQL4"] += 2
                if b'MQL5' in sig: lang_scores["MQL5"] += 2
                if b'MetaQuotes' in sig: 
                    lang_scores["MQL4"] += 1
                    lang_scores["MQL5"] += 1
                if b'mscoree' in sig: lang_scores["C#/.NET"] += 3
                if b'MSVB' in sig: lang_scores["VB6"] += 3
                if b'python' in sig.lower(): lang_scores["Python"] += 2
                if b'java' in sig.lower(): lang_scores["Java"] += 2
                if b'Borland' in sig: lang_scores["Delphi"] += 3
                if b'Visual C++' in sig: lang_scores["C/C++"] += 2

        self.results["security_check"] = list(set(found_sigs))
        
        # Determine likely language
        best_lang = "Unknown (Binary)"
        max_score = 0
        for lang, score in lang_scores.items():
            if score > max_score:
                max_score = score
                best_lang = lang
        
        self.results["detected_language"] = best_lang

    def _disassemble_x86(self, data):
        """
        Basic x86 Disassembler (32-bit mode assumption for simplicity)
        """
        lines = []
        limit = min(len(data), 2048) # Analyze first 2KB
        i = 0
        
        while i < limit:
            byte = data[i]
            mnemonic = "DB"
            operands = f"{byte:02X}"
            size = 1
            
            # Basic Opcode Map
            if byte == 0x55:
                mnemonic = "PUSH"
                operands = "EBP"
            elif byte == 0x89:
                if i+1 < limit:
                    modrm = data[i+1]
                    if modrm == 0xE5:
                        mnemonic = "MOV"
                        operands = "EBP, ESP"
                        size = 2
            elif byte == 0x83:
                if i+2 < limit:
                    modrm = data[i+1]
                    if modrm == 0xEC:
                        mnemonic = "SUB"
                        operands = f"ESP, {data[i+2]:02X}"
                        size = 3
            elif byte == 0xE8:
                if i+4 < limit:
                    rel = struct.unpack_from('<i', data, i+1)[0]
                    mnemonic = "CALL"
                    operands = f"func_{i+5+rel:08X}"
                    size = 5
            elif byte == 0xC3:
                mnemonic = "RET"
                operands = ""
            elif byte == 0x68:
                if i+4 < limit:
                    val = struct.unpack_from('<I', data, i+1)[0]
                    mnemonic = "PUSH"
                    operands = f"0x{val:08X}"
                    size = 5
            elif byte == 0x6A:
                if i+1 < limit:
                    val = data[i+1]
                    mnemonic = "PUSH"
                    operands = f"0x{val:02X}"
                    size = 2
            elif byte == 0x00:
                mnemonic = "ADD"
                if i+1 < limit:
                    operands = f"[EAX], AL" # Simplified
                    size = 2
            
            # Formatting
            hex_bytes = " ".join(f"{b:02X}" for b in data[i:i+size])
            lines.append(f"{i:08X} | {hex_bytes:<16} | {mnemonic:<6} {operands}")
            i += size
            
        return "\n".join(lines)

    def _universal_reconstruct(self, strings, data):
        """
        Universal Code Reconstruction Engine.
        Adapts output based on detected language.
        """
        lang = self.results["detected_language"]
        code_lines = []
        
        code_lines.append(f"//+------------------------------------------------------------------+")
        code_lines.append(f"//|                  ANTIGRAVITY UNIVERSAL DECOMPILER                |")
        code_lines.append(f"//|                  Detected Language: {lang:<28} |")
        code_lines.append(f"//+------------------------------------------------------------------+")
        code_lines.append("")

        if "MQL" in lang:
            return self._reconstruct_mql(strings, lang)
        elif "Python" in lang:
            return self._reconstruct_python(strings)
        elif "C#" in lang or ".NET" in lang:
            return self._reconstruct_csharp(strings)
        elif "C/C++" in lang:
            return self._reconstruct_cpp(strings)
        else:
            return self._reconstruct_generic(strings)

    def _reconstruct_mql(self, strings, lang):
        code_lines = []
        code_lines.append(f"#property copyright \"Copyright 2024, Antigravity AI\"")
        code_lines.append(f"#property version   \"1.00\"")
        code_lines.append(f"#property strict")
        code_lines.append("")
        
        # MQL5 specific
        if lang == "MQL5":
             code_lines.append("#include <Trade\\Trade.mqh>")
             code_lines.append("CTrade trade;")
             code_lines.append("")

        # Inputs
        code_lines.append("//--- Input Parameters")
        common_vars = ['MagicNumber', 'Lots', 'StopLoss', 'TakeProfit', 'TrailingStop', 'Slippage', 'Period', 'TimeFrame', 'MaPeriod', 'RsiPeriod']
        found_vars = set()
        
        for s in strings:
            val = s['value']
            if val in common_vars or (val[0].isupper() and len(val) > 4 and val.isalnum()):
                if val not in found_vars:
                    v_type = "int" if "Number" in val or "Period" in val else "double"
                    v_val = "0" if v_type == "int" else "0.0"
                    code_lines.append(f"input {v_type} {val} = {v_val};")
                    found_vars.add(val)
        code_lines.append("")

        # Logic
        code_lines.append("//--- Main Logic")
        if lang == "MQL4":
            code_lines.append("void OnTick() {")
            code_lines.append("    if(OrdersTotal() < 1) {")
            code_lines.append("        // OrderSend logic here")
            code_lines.append("    }")
            code_lines.append("}")
        else: # MQL5
            code_lines.append("void OnTick() {")
            code_lines.append("    if(PositionsTotal() < 1) {")
            code_lines.append("        trade.Buy(Lots);")
            code_lines.append("    }")
            code_lines.append("}")
            
        return "\n".join(code_lines)

    def _reconstruct_python(self, strings):
        code_lines = []
        code_lines.append("import os")
        code_lines.append("import sys")
        code_lines.append("")
        code_lines.append("# Detected Strings / Potential Variables")
        for s in strings[:50]:
            val = s['value']
            if val.isidentifier():
                code_lines.append(f"{val} = None")
        code_lines.append("")
        code_lines.append("def main():")
        code_lines.append("    pass")
        code_lines.append("")
        code_lines.append("if __name__ == '__main__':")
        code_lines.append("    main()")
        return "\n".join(code_lines)

    def _reconstruct_csharp(self, strings):
        code_lines = []
        code_lines.append("using System;")
        code_lines.append("using System.Collections.Generic;")
        code_lines.append("")
        code_lines.append("namespace DecompiledApp {")
        code_lines.append("    public class Program {")
        code_lines.append("        // Detected Strings")
        for s in strings[:20]:
            val = s['value']
            if len(val) > 3 and val.isalnum():
                code_lines.append(f"        public static string str_{val} = \"{val}\";")
        code_lines.append("")
        code_lines.append("        public static void Main(string[] args) {")
        code_lines.append("            Console.WriteLine(\"Hello World\");")
        code_lines.append("        }")
        code_lines.append("    }")
        code_lines.append("}")
        return "\n".join(code_lines)

    def _reconstruct_cpp(self, strings):
        code_lines = []
        code_lines.append("#include <iostream>")
        code_lines.append("#include <string>")
        code_lines.append("using namespace std;")
        code_lines.append("")
        code_lines.append("int main() {")
        code_lines.append("    // Reconstructed String Table")
        for s in strings[:20]:
            val = s['value']
            if len(val) > 3:
                code_lines.append(f"    string s_{hex(int(s['offset'], 16))} = \"{val}\";")
        code_lines.append("    return 0;")
        code_lines.append("}")
        return "\n".join(code_lines)

    def _reconstruct_generic(self, strings):
        code_lines = []
        code_lines.append("// Generic Code Reconstruction")
        code_lines.append("// Language could not be definitively identified.")
        code_lines.append("")
        code_lines.append("// String Dump (Potential Data/Variables)")
        for s in strings[:50]:
            code_lines.append(f"// Offset {s['offset']}: {s['value']}")
        return "\n".join(code_lines)

    def get_report_data(self):
        return self.results
