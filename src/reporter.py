import json
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    """Generate reports in various formats"""
    
    @staticmethod
    def generate_json_report(analysis_results: Dict[str, Any]) -> str:
        """Generate JSON report"""
        report = {
            "threat_hunter_lite_report": {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "version": "1.0",
                    "tool": "ThreatHunter Lite"
                },
                "summary": analysis_results.get("summary", {}),
                "detailed_findings": analysis_results.get("detections", {})
            }
        }
        return json.dumps(report, indent=2, default=str)
    
    @staticmethod
    def generate_text_report(analysis_results: Dict[str, Any]) -> str:
        """Generate human-readable text report"""
        summary = analysis_results.get("summary", {})
        detections = analysis_results.get("detections", {})
        
        # Build report line by line to avoid f-string complexity
        report_lines = []
        report_lines.append("THREAT HUNTER LITE - SECURITY ANALYSIS REPORT")
        report_lines.append("=" * 50)
        report_lines.append("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        report_lines.append("Risk Score: " + str(analysis_results.get("risk_score", 0)) + "/100")
        report_lines.append("Risk Level: " + summary.get("risk_level", "UNKNOWN"))
        report_lines.append("Total Detections: " + str(summary.get("total_detections", 0)))
        report_lines.append("")
        report_lines.append("DETAILED FINDINGS:")
        report_lines.append("-" * 30)
        
        for category, findings in detections.items():
            if findings:
                report_lines.append("")
                report_lines.append(category.upper().replace("_", " ") + ":")
                for i, finding in enumerate(findings, 1):
                    report_lines.append("  " + str(i) + ". " + finding.get("evidence", "No details"))
                    report_lines.append("     MITRE: " + finding.get("mitre_technique", "Unknown"))
                    report_lines.append("     Risk: " + str(finding.get("risk_score", 0)))
        
        return "\n".join(report_lines)
    
    @staticmethod
    def save_report(report_content: str, filename: str, format_type: str = "json"):
        """Save report to file"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_content)
        print("Report saved: " + filename)

class MITREMapper:
    """Map findings to MITRE ATT&CK framework"""
    
    TECHNIQUES = {
        "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
        "T1136": {"name": "Create Account", "tactic": "Persistence"},
        "T1091": {"name": "External Device", "tactic": "Lateral Movement"},
        "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
        "T1068": {"name": "Privilege Escalation", "tactic": "Privilege Escalation"}
    }
    
    @staticmethod
    def get_mitre_matrix(findings: Dict) -> Dict:
        """Generate MITRE ATT&CK mapping"""
        matrix = {}
        
        for category, detection_list in findings.items():
            for detection in detection_list:
                technique_id = detection.get("mitre_technique", "").split(" - ")[0]
                if technique_id in MITREMapper.TECHNIQUES:
                    tech_info = MITREMapper.TECHNIQUES[technique_id]
                    if technique_id not in matrix:
                        matrix[technique_id] = {
                            "technique": tech_info["name"],
                            "tactic": tech_info["tactic"],
                            "occurrences": 0,
                            "examples": []
                        }
                    matrix[technique_id]["occurrences"] += 1
                    matrix[technique_id]["examples"].append(detection.get("evidence", ""))
        
        return matrix
