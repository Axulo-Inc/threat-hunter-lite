from datetime import datetime, timedelta
import random

def generate_sample_logs():
    """Generate sample log files for testing"""
    
    # Sample Windows events
    windows_events = [
        "2024-01-15 10:30:00, WARNING, Security, 4625, Failed login for user admin from 192.168.1.100",
        "2024-01-15 10:30:01, WARNING, Security, 4625, Failed login for user admin from 192.168.1.100",
        "2024-01-15 10:30:02, WARNING, Security, 4625, Failed login for user admin from 192.168.1.100",
        "2024-01-15 10:30:03, WARNING, Security, 4625, Failed login for user admin from 192.168.1.100",
        "2024-01-15 10:30:04, WARNING, Security, 4625, Failed login for user admin from 192.168.1.100",
        "2024-01-15 10:35:00, INFO, Security, 4720, New user account created: suspicious_user",
        "2024-01-15 10:40:00, INFO, System, 20001, USB Device installed: Unknown USB Mass Storage",
        "2024-01-15 11:00:00, INFO, Security, 4672, Special privileges assigned to new logon",
    ]
    
    # Sample Linux auth logs
    linux_events = [
        "Jan 15 10:30:00 ubuntu sshd[1234]: Failed password for root from 10.0.0.100 port 22 ssh2",
        "Jan 15 10:30:01 ubuntu sshd[1235]: Failed password for root from 10.0.0.100 port 22 ssh2",
        "Jan 15 10:30:02 ubuntu sshd[1236]: Failed password for root from 10.0.0.100 port 22 ssh2",
        "Jan 15 10:30:03 ubuntu sshd[1237]: Failed password for root from 10.0.0.100 port 22 ssh2",
        "Jan 15 10:30:04 ubuntu sshd[1238]: Failed password for root from 10.0.0.100 port 22 ssh2",
        "Jan 15 10:35:00 ubuntu useradd[1239]: new user: name=suspicious_linux, UID=1001",
        "Jan 15 10:40:00 ubuntu sudo:     admin : TTY=pts/0 ; PWD=/home/admin ; USER=root",
    ]
    
    with open("samples/windows_events.log", "w") as f:
        f.write("\n".join(windows_events))
    
    with open("samples/linux_auth.log", "w") as f:
        f.write("\n".join(linux_events))
    
    print("Sample log files generated in samples/ directory")

if __name__ == "__main__":
    generate_sample_logs()
