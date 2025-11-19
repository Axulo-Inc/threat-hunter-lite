import pandas as pd
import json
import re
from datetime import datetime
from typing import Dict, List, Any

# Fix the import - use absolute import
try:
    from patterns import DetectionPatterns
except ImportError:
    from .patterns import DetectionPatterns

class LogAnalyzer:
    """Main log analysis engine"""
    
    def __init__(self):
        self.patterns = DetectionPatterns()
        self.detection_results = {}
        self.risk_score = 0
        
    def parse_windows_logs(self, log_file: str) -> List[Dict]:
        """Parse Windows Event Logs"""
        logs = []
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        log_entry = self._parse_windows_line(line)
                        if log_entry:
                            logs.append(log_entry)
        except Exception as e:
            print(f"Error parsing Windows logs: {e}")
        return logs
    
    def parse_linux_logs(self, log_file: str) -> List[Dict]:
        """Parse Linux system logs"""
        logs = []
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        log_entry = self._parse_linux_line(line)
                        if log_entry:
                            logs.append(log_entry)
        except Exception as e:
            print(f"Error parsing Linux logs: {e}")
        return logs
    
    def _parse_windows_line(self, line: str) -> Dict:
        """Parse individual Windows log line"""
        # Simplified parser - extend based on your log format
        try:
            # Example: "2024-01-15 10:30:00, INFO, Security, 4625, Failed login"
            parts = line.split(",")
            if len(parts) >= 5:
                # Extract IP address from message if present
                message = parts[4].strip()
                source_ip = "unknown"
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", message)
                if ip_match:
                    source_ip = ip_match.group(1)
                
                # Extract username from message if present
                username = "unknown"
                user_match = re.search(r"user (\w+)", message, re.IGNORECASE)
                if user_match:
                    username = user_match.group(1)
                
                return {
                    "timestamp": self._parse_timestamp(parts[0].strip()),
                    "level": parts[1].strip(),
                    "source": parts[2].strip(),
                    "event_id": parts[3].strip(),
                    "message": message,
                    "source_ip": source_ip,
                    "username": username,
                    "log_type": "windows"
                }
        except Exception as e:
            print(f"Error parsing Windows line: {e}")
        return None
    
    def _parse_linux_line(self, line: str) -> Dict:
        """Parse individual Linux log line"""
        try:
            # Example: "Jan 15 10:30:00 ubuntu sshd[1234]: Failed password for root from 10.0.0.100 port 22 ssh2"
            timestamp_match = re.match(r"^(\w+ \d+ \d+:\d+:\d+)", line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                
                # Extract IP address
                source_ip = "unknown"
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    source_ip = ip_match.group(1)
                
                # Extract username
                username = "unknown"
                user_match = re.search(r"for (\w+)", line)
                if user_match:
                    username = user_match.group(1)
                
                return {
                    "timestamp": self._parse_timestamp(timestamp_str),
                    "hostname": "ubuntu",
                    "process": "sshd",
                    "message": line,
                    "source_ip": source_ip,
                    "username": username,
                    "log_type": "linux"
                }
        except Exception as e:
            print(f"Error parsing Linux line: {e}")
        return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp from string"""
        try:
            # Add more timestamp formats as needed
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%b %d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            return datetime.now()
        except:
            return datetime.now()
    
    def analyze_logs(self, logs: List[Dict]) -> Dict[str, Any]:
        """Run all detection patterns on logs"""
        # Filter out None values
        valid_logs = [log for log in logs if log is not None]
        
        self.detection_results = {
            "repeated_failed_logins": self.patterns.repeated_failed_logins(valid_logs),
            "unknown_user_creation": self.patterns.unknown_user_creation(valid_logs),
            "usb_device_connections": self.patterns.usb_device_connections(valid_logs),
            "suspicious_ip_attempts": self.patterns.suspicious_ip_attempts(valid_logs),
            "privilege_escalation": self.patterns.privilege_escalation_attempts(valid_logs)
        }
        
        # Calculate overall risk score
        self.risk_score = self._calculate_risk_score()
        
        return {
            "detections": self.detection_results,
            "risk_score": self.risk_score,
            "summary": self._generate_summary()
        }
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)"""
        total_risk = 0
        detection_count = 0
        
        for category, detections in self.detection_results.items():
            for detection in detections:
                total_risk += detection.get("risk_score", 0)
                detection_count += 1
        
        if detection_count == 0:
            return 0
        
        avg_risk = total_risk / detection_count
        # Scale based on number of detections
        severity_multiplier = min(1.0, detection_count / 10)
        
        return min(100, int(avg_risk * severity_multiplier))
    
    def _generate_summary(self) -> Dict:
        """Generate analysis summary"""
        total_detections = sum(len(detections) for detections in self.detection_results.values())
        
        return {
            "total_detections": total_detections,
            "risk_level": self._get_risk_level(self.risk_score),
            "timestamp": datetime.now().isoformat(),
            "categories_affected": [
                category for category, detections in self.detection_results.items() 
                if len(detections) > 0
            ]
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"
