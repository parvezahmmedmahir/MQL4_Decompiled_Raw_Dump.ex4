import json
import html
import re

class ReportGenerator:
    def __init__(self, analysis_results):
        self.data = analysis_results

    def generate_html(self, output_path):
        html_content = self._build_html()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path

    def generate_text_report(self, output_path):
        text_content = self._build_text()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(text_content)
        return output_path

    def _build_text(self):
        lines = []
        lines.append("="*60)
        lines.append("   ANTIGRAVITY UNIVERSAL BINARY ANALYSIS REPORT")
        lines.append("="*60)
        
        # File Info
        lines.append("\n[FILE INFORMATION]")
        for k, v in self.data.get("file_info", {}).items():
            lines.append(f"{k:<15}: {v}")
        
        lines.append(f"Entropy        : {self.data.get('entropy', 0.0):.4f} (High > 7.0 = Packed/Encrypted)")
        lines.append(f"Detected Lang  : {self.data.get('detected_language', 'Unknown')}")

        # Version Info
        lines.append("\n[VERSION INFO]")
        ver_info = self.data.get("version_info", {})
        if ver_info:
            for k, v in ver_info.items():
                lines.append(f"{k:<20}: {v}")
        else:
            lines.append("No version information found.")

        # Headers
        lines.append("\n[PE HEADERS]")
        if self.data.get("headers"):
            for k, v in self.data.get("headers", {}).items():
                lines.append(f"{k:<15}: {v}")
        else:
            lines.append("No PE Headers detected.")

        # Sections
        lines.append("\n[SECTIONS]")
        sections = self.data.get("sections", [])
        if sections:
            lines.append(f"{'Name':<10} {'VirtSize':<10} {'VirtAddr':<10} {'RawSize':<10} {'RawPtr':<10}")
            lines.append("-" * 55)
            for s in sections:
                lines.append(f"{s['Name']:<10} {s['VirtSize']:<10} {s['VirtAddr']:<10} {s['RawSize']:<10} {s['RawPtr']:<10}")
        else:
            lines.append("No sections found.")

        # Imports
        lines.append("\n[IMPORTED LIBRARIES]")
        imports = self.data.get("imports", [])
        if imports:
            for imp in imports:
                lines.append(f"- {imp}")
        else:
            lines.append("No imports found.")

        # Security
        lines.append("\n[SECURITY & SIGNATURES]")
        security = self.data.get("security_check", [])
        if security:
            for s in security:
                lines.append(f"[!] {s}")
        else:
            lines.append("No suspicious signatures found.")

        # Strings (Top 50)
        lines.append("\n[STRINGS (First 50)]")
        strings = self.data.get("strings", [])
        for s in strings[:50]:
            lines.append(f"{s['offset']}: {s['value']}")

        # Assembly
        lines.append("\n[DISASSEMBLY PREVIEW (First 2KB)]")
        lines.append(self.data.get("assembly_view", ""))
        
        # Reconstructed Code
        lines.append("\n[RECONSTRUCTED SOURCE CODE]")
        lines.append(self.data.get("reconstructed_code", ""))

        return "\n".join(lines)

    def _build_html(self):
        file_info = self.data.get("file_info", {})
        headers = self.data.get("headers", {})
        strings = self.data.get("strings", [])
        security = self.data.get("security_check", [])
        sections = self.data.get("sections", [])
        imports = self.data.get("imports", [])
        entropy = self.data.get("entropy", 0.0)
        detected_lang = self.data.get("detected_language", "Unknown")
        reconstructed_code = self.data.get("reconstructed_code", "// No code reconstructed.")
        assembly_view = self.data.get("assembly_view", "; No assembly generated.")
        version_info = self.data.get("version_info", {})
        
        display_strings = strings[:2000] 
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ANTIGRAVITY // UNIVERSAL DECODER</title>
    <style>
        :root {{
            --bg-dark: #1e1e1e;
            --bg-panel: #252526;
            --primary: #007acc;
            --accent: #4ec9b0;
            --text-main: #d4d4d4;
            --text-dim: #858585;
            --border: #3e3e42;
            --font-mono: 'Consolas', 'Courier New', monospace;
            --font-ui: 'Segoe UI', system-ui, sans-serif;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: var(--font-ui);
            overflow-x: hidden;
            line-height: 1.6;
        }}

        ::-webkit-scrollbar {{ width: 10px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg-dark); }}
        ::-webkit-scrollbar-thumb {{ background: #424242; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #4f4f4f; }}

        header {{
            border-bottom: 1px solid var(--border);
            padding: 0.5rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #333333;
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .brand {{
            font-family: var(--font-ui);
            font-weight: 600;
            font-size: 1rem;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .brand span {{ color: #ccc; font-weight: 400; }}

        .container {{
            max-width: 100%;
            padding: 0;
            display: grid;
            grid-template-columns: 320px 1fr;
            height: calc(100vh - 50px);
        }}

        .sidebar {{
            background: var(--bg-panel);
            border-right: 1px solid var(--border);
            padding: 1rem;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .card {{
            background: #2d2d30;
            border: 1px solid var(--border);
            padding: 10px;
            font-size: 0.9rem;
        }}

        .card-title {{
            font-weight: 600;
            color: var(--text-dim);
            margin-bottom: 5px;
            font-size: 0.8rem;
            text-transform: uppercase;
        }}

        .main-content {{
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            padding: 1rem;
            gap: 2rem;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }}

        .section-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: #fff;
        }}

        .code-block {{
            background: #1e1e1e;
            border: 1px solid var(--border);
            padding: 1rem;
            font-family: var(--font-mono);
            font-size: 13px;
            overflow-x: auto;
            color: #d4d4d4;
            white-space: pre;
            tab-size: 4;
        }}

        /* Syntax Highlighting */
        .hl-keyword {{ color: #569cd6; font-weight: bold; }}
        .hl-type {{ color: #4ec9b0; }}
        .hl-string {{ color: #ce9178; }}
        .hl-comment {{ color: #6a9955; }}
        .hl-func {{ color: #dcdcaa; }}
        .hl-num {{ color: #b5cea8; }}

        .assembly-view {{
            font-family: var(--font-mono);
            font-size: 12px;
            color: #9cdcfe;
            background: #101010;
        }}
        
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th, td {{ text-align: left; padding: 4px; border-bottom: 1px solid #3e3e42; }}
        th {{ color: var(--text-dim); }}

    </style>
</head>
<body>
    <header>
        <div class="brand">
            ANTIGRAVITY <span>UNIVERSAL DECODER SYSTEM</span>
        </div>
        <div style="font-size: 0.8rem; color: #fff; background: #007acc; padding: 2px 8px; border-radius: 2px;">
            v3.0 ULTRA
        </div>
    </header>

    <div class="container">
        <aside class="sidebar">
            <div class="card">
                <div class="card-title">File Information</div>
                <div style="color: #fff;">{html.escape(str(file_info.get('Source', 'Unknown')))}</div>
                <div style="color: var(--text-dim);">{file_info.get('Size', '0 bytes')}</div>
                <div style="color: var(--accent); margin-top: 5px;">{file_info.get('Type', 'Unknown')}</div>
                <div style="margin-top: 5px;">Entropy: <span style="color: {'#ff5555' if entropy > 7.0 else '#4ec9b0'}">{entropy:.4f}</span></div>
            </div>

            <div class="card">
                <div class="card-title">Detected Language</div>
                <div style="color: #ce9178; font-weight: bold; font-size: 1.1rem;">{detected_lang}</div>
            </div>

            <div class="card">
                <div class="card-title">Detected Signatures</div>
                <div>
                    {''.join([f'<div style="color: #ce9178;">• {s}</div>' for s in security]) if security else '<div style="color: var(--text-dim)">None</div>'}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Version Info</div>
                <div style="font-family: var(--font-mono); font-size: 0.8rem;">
                    {self._format_dict(version_info) if version_info else '<div style="color: var(--text-dim)">None</div>'}
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">PE Headers</div>
                <div style="font-family: var(--font-mono); font-size: 0.8rem;">
                    {self._format_dict(headers)}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Imported Libraries</div>
                <div style="font-family: var(--font-mono); font-size: 0.8rem; max-height: 150px; overflow-y: auto;">
                    {''.join([f'<div>{imp}</div>' for imp in imports]) if imports else 'None'}
                </div>
            </div>
        </aside>

        <main class="main-content">
            <!-- SECTIONS -->
            <section>
                 <div class="section-header">
                    <h2 class="section-title">PE Sections</h2>
                </div>
                <div class="code-block">
                    <table>
                        <tr><th>Name</th><th>VirtSize</th><th>VirtAddr</th><th>RawSize</th><th>RawPtr</th></tr>
                        {''.join([f"<tr><td>{s['Name']}</td><td>{s['VirtSize']}</td><td>{s['VirtAddr']}</td><td>{s['RawSize']}</td><td>{s['RawPtr']}</td></tr>" for s in sections])}
                    </table>
                </div>
            </section>

            <!-- RECONSTRUCTED SOURCE CODE -->
            <section>
                <div class="section-header">
                    <h2 class="section-title">Reconstructed Source Code ({detected_lang})</h2>
                </div>
                <div class="code-block">
{self._highlight_code(reconstructed_code)}
                </div>
            </section>

            <!-- ASSEMBLY VIEW -->
            <section>
                <div class="section-header">
                    <h2 class="section-title">Disassembly / Bytecode</h2>
                </div>
                <div class="code-block assembly-view">
{html.escape(assembly_view)}
                </div>
            </section>

            <!-- STRINGS -->
            <section>
                <div class="section-header">
                    <h2 class="section-title">String Table</h2>
                </div>
                <div class="code-block" style="max-height: 300px; overflow-y: auto;">
                    {self._format_strings(display_strings)}
                </div>
            </section>
        </main>
    </div>
</body>
</html>
        """

    def _format_dict(self, d):
        return "".join([f"<div style='display:flex; justify-content:space-between; margin-bottom:4px;'><span>{k}:</span> <span style='color:#fff'>{v}</span></div>" for k, v in d.items()])

    def _format_strings(self, strings):
        lines = []
        for s in strings:
            lines.append(f'<div><span style="color: #569cd6;">{s["offset"]}</span>  <span style="color: #ce9178;">"{html.escape(s["value"])}"</span></div>')
        return "".join(lines)

    def _highlight_code(self, code):
        # Basic Syntax Highlighting
        escaped = html.escape(code)
        
        keywords = ["int", "double", "void", "bool", "string", "extern", "input", "if", "else", "return", "for", "while", 
                    "class", "public", "private", "import", "def", "using", "namespace"]
        
        for kw in keywords:
            escaped = re.sub(r'\b' + kw + r'\b', f'<span class="hl-keyword">{kw}</span>', escaped)
            
        # Comments
        lines = escaped.split('\n')
        final_lines = []
        for line in lines:
            if "//" in line:
                parts = line.split("//", 1)
                line = parts[0] + f'<span class="hl-comment">//{parts[1]}</span>'
            elif "#" in line and "include" not in line and "property" not in line: # Python style comments
                 parts = line.split("#", 1)
                 line = parts[0] + f'<span class="hl-comment">#{parts[1]}</span>'
            final_lines.append(line)
            
        return "\n".join(final_lines)
