# ThreatHunter Lite 🔍

A lightweight log analysis tool for detecting suspicious activities in system logs.

## Features
- Multi-platform log support (Windows Event Logs, Linux auth logs)
- Detection of common attack patterns
- MITRE ATT&CK mapping
- Risk scoring and reporting
- GUI and CLI interfaces

## Installation
\`\`\`bash
git clone https://github.com/yourusername/threat-hunter-lite
cd threat-hunter-lite
pip install -r requirements.txt
\`\`\`

## Usage
\`\`\`bash
# CLI - Windows logs
python main.py --logfile samples/windows_events.log --type windows --format text

# CLI - Linux logs  
python main.py --logfile samples/linux_auth.log --type linux --format json

# Save reports to files
python main.py --logfile samples/windows_events.log --type windows --format text --output report.txt

# GUI mode
python main.py --gui
\`\`\`

## Detection Patterns
- Repeated failed login attempts
- Unknown user account creation
- USB device connections
- Suspicious IP addresses
- Privilege escalation attempts

## Technologies
- Python 3
- pandas for data analysis
- MITRE ATT&CK framework mapping
