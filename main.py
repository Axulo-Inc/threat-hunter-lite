#!/usr/bin/env python3
"""
ThreatHunter Lite - A Basic Log Analyzer
Author: Your Name
Version: 1.0
"""

import argparse
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from analyzer import LogAnalyzer
from reporter import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="ThreatHunter Lite - Log Analysis Tool")
    parser.add_argument("--logfile", help="Path to log file")
    parser.add_argument("--type", choices=["windows", "linux"], help="Log type")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    parser.add_argument("--gui", action="store_true", help="Launch GUI interface")
    
    args = parser.parse_args()
    
    if args.gui:
        try:
            from gui import ThreatHunterGUI
            import tkinter as tk
            root = tk.Tk()
            app = ThreatHunterGUI(root)
            root.mainloop()
        except ImportError as e:
            print(f"GUI not available: {e}")
            print("Running in CLI mode instead...")
    elif args.logfile and args.type:
        # CLI mode
        analyzer = LogAnalyzer()
        
        if args.type == "windows":
            logs = analyzer.parse_windows_logs(args.logfile)
        else:
            logs = analyzer.parse_linux_logs(args.logfile)
        
        if not logs:
            print("Error: No logs could be parsed")
            return
        
        results = analyzer.analyze_logs(logs)
        
        if args.format == "json":
            report = ReportGenerator.generate_json_report(results)
        else:
            report = ReportGenerator.generate_text_report(results)
        
        if args.output:
            ReportGenerator.save_report(report, args.output, args.format)
        else:
            print(report)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
