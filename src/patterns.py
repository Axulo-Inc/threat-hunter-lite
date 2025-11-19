import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any

class DetectionPatterns:
    """Detection patterns for suspicious activities"""
    
    @staticmethod
    def repeated_failed_logins(logs: List[Dict], threshold: int = 5, window_minutes: int = 10) -> List[Dict]:
        """Detect repeated failed login attempts"""
        suspicious_attempts = []
        
        # Group by source IP and username
        attempts_by_ip_user = {}
        
        for log in logs:
            if "failed" in log.get("message", "").lower() or log.get("event_id") in [4625, 535]:
                ip = log.get("source_ip", "unknown")
                user = log.get("username", "unknown")
                timestamp = log.get("timestamp")
                
                key = (ip, user)
                if key not in attempts_by_ip_user:
                    attempts_by_ip_user[key] = []
                attempts_by_ip_user[key].append(timestamp)
        
        # Check for threshold violations
        for (ip, user), timestamps in attempts_by_ip_user.items():
            if len(timestamps) >= threshold:
                # Check if attempts are within time window
                sorted_times = sorted(timestamps)
                for i in range(len(sorted_times) - threshold + 1):
                    time_diff = sorted_times[i + threshold - 1] - sorted_times[i]
                    if time_diff <= timedelta(minutes=window_minutes):
                        suspicious_attempts.append({
                            "ip_address": ip,
                            "username": user,
                            "attempt_count": len(timestamps),
                            "time_window": f"{window_minutes} minutes",
                            "mitre_technique": "T1110 - Brute Force",
                            "risk_score": 85,
                            "evidence": f"{len(timestamps)} failed login attempts from {ip}"
                        })
                        break
        
        return suspicious_attempts
    
    @staticmethod
    def unknown_user_creation(logs: List[Dict], known_users: List[str] = None) -> List[Dict]:
        """Detect creation of unknown user accounts"""
        if known_users is None:
            known_users = ["root", "admin", "administrator", "system"]
        
        suspicious_creations = []
        user_creation_patterns = [
            r"user.*add", r"user.*created", r"account.*created",
            r"event_id.*4720", r"event_id.*4741"  # Windows user creation events
        ]
        
        for log in logs:
            message = log.get("message", "").lower()
            if any(re.search(pattern, message) for pattern in user_creation_patterns):
                # Extract username from log message
                username_match = re.search(r"user[:\s]+([^\s,]+)", message, re.IGNORECASE)
                if username_match:
                    username = username_match.group(1).lower()
                    if username not in known_users:
                        suspicious_creations.append({
                            "username": username,
                            "timestamp": log.get("timestamp"),
                            "source": log.get("source_ip", "unknown"),
                            "mitre_technique": "T1136 - Create Account",
                            "risk_score": 75,
                            "evidence": f"New user account created: {username}"
                        })
        
        return suspicious_creations
    
    @staticmethod
    def usb_device_connections(logs: List[Dict]) -> List[Dict]:
        """Detect USB device connections"""
        usb_connections = []
        usb_patterns = [
            r"usb", r"device.*installed", r"hardware.*insert",
            r"event_id.*6416", r"event_id.*20001"  # Windows USB events
        ]
        
        for log in logs:
            message = log.get("message", "").lower()
            if any(re.search(pattern, message) for pattern in usb_patterns):
                # Extract device info
                device_info = re.search(r"device[:\s]+([^\n]+)", message, re.IGNORECASE)
                device_name = device_info.group(1) if device_info else "Unknown USB Device"
                
                usb_connections.append({
                    "device_name": device_name,
                    "timestamp": log.get("timestamp"),
                    "source": log.get("source_ip", "localhost"),
                    "mitre_technique": "T1091 - External Device",
                    "risk_score": 60,
                    "evidence": f"USB device connected: {device_name}"
                })
        
        return usb_connections
    
    @staticmethod
    def suspicious_ip_attempts(logs: List[Dict], suspicious_ips: List[str] = None) -> List[Dict]:
        """Detect connection attempts from suspicious IPs"""
        if suspicious_ips is None:
            # Example suspicious IP ranges (you can expand this)
            suspicious_ips = [
                "10.0.0.100", "192.168.1.200"  # Add known malicious IPs
            ]
        
        suspicious_attempts = []
        
        for log in logs:
            source_ip = log.get("source_ip")
            if source_ip and source_ip in suspicious_ips:
                suspicious_attempts.append({
                    "ip_address": source_ip,
                    "timestamp": log.get("timestamp"),
                    "event_type": log.get("event_type", "Unknown"),
                    "mitre_technique": "T1078 - Valid Accounts",
                    "risk_score": 90,
                    "evidence": f"Connection from known suspicious IP: {source_ip}"
                })
        
        return suspicious_attempts
    
    @staticmethod
    def privilege_escalation_attempts(logs: List[Dict]) -> List[Dict]:
        """Detect privilege escalation attempts"""
        privilege_patterns = [
            r"sudo", r"runas", r"privilege.*escalat", r"event_id.*4672"
        ]
        
        escalation_attempts = []
        
        for log in logs:
            message = log.get("message", "").lower()
            if any(re.search(pattern, message) for pattern in privilege_patterns):
                escalation_attempts.append({
                    "timestamp": log.get("timestamp"),
                    "username": log.get("username", "unknown"),
                    "source_ip": log.get("source_ip", "unknown"),
                    "mitre_technique": "T1068 - Privilege Escalation",
                    "risk_score": 80,
                    "evidence": f"Privilege escalation attempt by {log.get('username', 'unknown')}"
                })
        
        return escalation_attempts
