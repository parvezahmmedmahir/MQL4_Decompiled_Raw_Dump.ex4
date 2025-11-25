import os
import sys
import webbrowser
import re
from analyzer import BinaryAnalyzer
from report_generator import ReportGenerator

def main():
    print("="*70)
    print("   ANTIGRAVITY ADVANCED BINARY DECODER & ANALYSIS SYSTEM")
    print("   World-Class PE/MQL4 Analysis | Disassembly | Reconstruction")
    print("="*70)
    
    analyzer = BinaryAnalyzer()
    target_data = None
    source_name = "Unknown"
    
    # 1. Check for arguments
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if os.path.exists(file_path):
            print(f"[*] Loading target file: {file_path}")
            analyzer.load_file(file_path)
            source_name = os.path.basename(file_path)
            target_data = True
        else:
            print(f"[!] File not found: {file_path}")
            return

    # 2. Check for input.txt
    elif os.path.exists("input.txt"):
        with open("input.txt", "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
            if content:
                # Check if content is a file path
                clean_path = content.strip('"').strip("'")
                if os.path.exists(clean_path) and os.path.isfile(clean_path):
                     print(f"[*] input.txt contains a valid file path: {clean_path}")
                     analyzer.load_file(clean_path)
                     source_name = os.path.basename(clean_path)
                else:
                    print("[*] Treating input.txt content as raw binary dump...")
                    analyzer.load_text_dump(content)
                    source_name = "Raw_Dump.ex4" # Assume EX4 for MQL4 context
                target_data = True

    # 3. Interactive Mode
    if not target_data:
        print("\n[?] No input detected.")
        print("    Option 1: Drag and drop an .EX4, .EXE, or System File here")
        print("    Option 2: Paste your code dump into 'input.txt' and run again")
        
        user_input = input("\n> Enter file path or press ENTER to exit: ").strip()
        
        if user_input:
            user_input = user_input.strip('"').strip("'")
            if os.path.exists(user_input):
                analyzer.load_file(user_input)
                source_name = os.path.basename(user_input)
                target_data = True
            else:
                print("[!] File not found.")
                return
        else:
            with open("input.txt", "w") as f:
                pass
            print("[*] Created 'input.txt'. Paste your code there and run this app again.")
            return

    # Run Analysis
    print("[*] Analyzing binary structure (PE/MQL4)...")
    print("[*] Calculating Entropy & Checking Signatures...")
    print("[*] Disassembling Code Sections (x86)...")
    print("[*] Reconstructing Logic Flow...")
    
    results = analyzer.get_report_data()
    
    print(f"[*] Analysis Complete. Found {len(results['strings'])} strings.")
    if results.get('entropy', 0) > 7.0:
        print("[!] WARNING: High Entropy detected! File might be packed or encrypted.")
    
    # Generate Reports
    generator = ReportGenerator(results)
    
    # HTML Report
    report_path_html = os.path.abspath(f"Analysis_Report_{source_name}.html")
    generator.generate_html(report_path_html)
    
    # Text Report
    report_path_txt = os.path.abspath(f"Analysis_Report_{source_name}.txt")
    generator.generate_text_report(report_path_txt)
    
    print(f"\n[SUCCESS] Reports Generated:")
    print(f"   [HTML] {report_path_html}")
    print(f"   [TEXT] {report_path_txt}")
    
    print("[*] Opening Report...")
    
    try:
        webbrowser.open(f"file://{report_path_html}")
        # Also try to open text file if possible, or just let user know
        os.startfile(report_path_txt) if os.name == 'nt' else None
    except:
        pass

if __name__ == "__main__":
    main()
