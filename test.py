#!/usr/bin/env python3
"""
Simple test script for ThreatHunter Lite
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from src.analyzer import LogAnalyzer
    from src.reporter import ReportGenerator
    
    print("Testing ThreatHunter Lite...")
    
    # Test Windows logs
    analyzer = LogAnalyzer()
    logs = analyzer.parse_windows_logs("samples/windows_events.log")
    
    if logs:
        print(f"Successfully parsed {len(logs)} log entries")
        results = analyzer.analyze_logs(logs)
        report = ReportGenerator.generate_text_report(results)
        print(report)
    else:
        print("No logs could be parsed")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
