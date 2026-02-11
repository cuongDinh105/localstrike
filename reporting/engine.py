"""
reporting/engine.py: Generates professional pentest reports from the agent's internal state.
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Literal

from state.manager import StateManager # To access the full state
from schemas.action import ToolMetadata # To get tool descriptions, risk, etc.
from config.settings import settings # For various thresholds and counts

logger = logging.getLogger(__name__)

class ReportEngine:
    """
    Converts the agent's internal StateManager data into a structured report.
    """
    def __init__(self, state_manager: StateManager, tool_metadata_map: Dict[str, ToolMetadata]):
        self.state_manager = state_manager
        self.tool_metadata_map = tool_metadata_map
        logger.info("ReportEngine initialized.")

    def _calculate_severity_score(self, finding: Dict[str, Any]) -> int:
        """
        Determines a deterministic severity score for a finding.
        (Part 3: Risk Scoring & Severity)
        """
        # Example scoring logic - this needs to be refined based on actual finding structure
        score = 0
        severity = finding.get("severity", "UNKNOWN").upper()
        
        if severity == "CRITICAL": score += 100
        elif severity == "HIGH": score += 70
        elif severity == "MEDIUM": score += 40
        elif severity == "LOW": score += 10
        elif severity == "INFORMATIONAL": score += 1

        # Adjust score based on evidence quality or tool confidence if available
        # For example: if finding['raw_output_ref'] is from a highly trusted tool, add bonus
        # if finding['confirmed_by_multiple_tools']: score += 10

        # Adjust for ambiguous/partial evidence
        # if finding.get("ambiguous_evidence"): score *= 0.7

        return score

    def _assign_qualitative_severity(self, score: int) -> Literal["Critical", "High", "Medium", "Low", "Informational", "Unknown"]:
        """Assigns qualitative severity based on the score."""
        if score >= 90: return "Critical"
        elif score >= 70: return "High"
        elif score >= 40: return "Medium"
        elif score >= 10: return "Low"
        else: return "Informational" if score > 0 else "Unknown"

    def _generate_findings_section(self) -> List[Dict[str, Any]]:
        """
        Generates the findings section of the report.
        (Part 2: Finding & Evidence Correlation)
        """
        report_findings = []
        # Sort findings by calculated severity
        sorted_findings = sorted(self.state_manager.findings, key=lambda f: self._calculate_severity_score(f), reverse=True)

        for finding in sorted_findings:
            # Re-calculate severity based on defined scoring model
            score = self._calculate_severity_score(finding)
            qualitative_severity = self._assign_qualitative_severity(score)

            # Get evidence
            evidence_detail = self.state_manager.raw_evidence_store.get(finding.get("raw_output_ref"), "Evidence not found.")
            
            # TODO: Enhance finding structure with suggested recommendations, CVSS, etc.
            report_findings.append({
                "id": finding["finding_id"],
                "title": finding["description"],
                "severity_score": score,
                "severity": qualitative_severity,
                "affected_asset": finding.get("affected_asset", "N/A"),
                "tool_identified_by": finding.get("tool_name", "N/A"),
                "description": finding["description"], # Can be expanded/rephrased here
                "recommendation": "TODO: Provide automated recommendation based on finding type.",
                "proof_of_concept": evidence_detail, # This would be the actual evidence content
                "raw_output_ref": finding.get("raw_output_ref"),
                "timestamp": finding.get("timestamp")
            })
        return report_findings

    def _generate_methodology_section(self) -> Dict[str, Any]:
        """
        Generates the methodology section.
        """
        methodology = {
            "overview": "The assessment followed a structured methodology, starting with reconnaissance, followed by active scanning and targeted analysis. Automated tools were orchestrated by the LocalStrike AI agent.",
            "phases": {
                "reconnaissance": {
                    "description": "Information gathering activities to map the target's external footprint.",
                    "tools_used": [],
                    "actions_count": 0
                },
                "scanning_analysis": {
                    "description": "Active scanning for open ports, services, and known vulnerabilities.",
                    "tools_used": [],
                    "actions_count": 0
                },
                # Add more phases as needed
            },
            "total_actions": len(self.state_manager.executed_actions_log)
        }

        tool_counts: Dict[str, int] = {}
        for action_entry in self.state_manager.executed_actions_log:
            tool_name = action_entry["internal_action"]["action"].get("tool_name", "internal")
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
            
            # Map tools to phases
            tool_meta = self.tool_metadata_map.get(tool_name)
            if tool_meta:
                if tool_meta.category == "recon":
                    if tool_meta.name not in methodology["phases"]["reconnaissance"]["tools_used"]:
                        methodology["phases"]["reconnaissance"]["tools_used"].append(tool_meta.name)
                    methodology["phases"]["reconnaissance"]["actions_count"] += 1
                elif tool_meta.category == "scanning" or tool_meta.category == "analysis":
                    if tool_meta.name not in methodology["phases"]["scanning_analysis"]["tools_used"]:
                        methodology["phases"]["scanning_analysis"]["tools_used"].append(tool_meta.name)
                    methodology["phases"]["scanning_analysis"]["actions_count"] += 1
        
        return methodology


    def generate_report_data_model(self) -> Dict[str, Any]:
        """
        Generates the full internal report data model from the current state.
        (Part 1: Report Data Model)
        """
        state = self.state_manager

        # Engagement Metadata
        total_time = (datetime.now() - state.start_time) if state.start_time else timedelta(0)
        report_meta = {
            "objective": state.objective,
            "initial_target": state.initial_target,
            "scope_notes": state.scope_notes,
            "start_time": state.start_time.isoformat() if state.start_time else "N/A",
            "end_time": datetime.now().isoformat(),
            "total_duration": str(total_time),
            "total_iterations": state.current_iteration,
            "final_status": "Completed" if state.objective_met else "Terminated Prematurely",
            "agent_version": "LocalStrike v1.0" # TODO: Make dynamic
        }

        # Scope Definition
        scope_definition = {
            "primary_target": state.initial_target,
            "known_assets": sorted(list(state.known_assets)),
            "discovered_subdomains": sorted(list(state.discovered_subdomains)),
            "discovered_ips": sorted(list(state.discovered_ips)),
            "blocked_assets": sorted(list(state.blocked_assets))
        }
        
        # Methodology
        methodology = self._generate_methodology_section()

        # Findings
        findings_data = self._generate_findings_section()
        
        # Risk Assessment
        risk_assessment = {
            "overall_risk_score": sum(self._calculate_severity_score(f) for f in state.findings),
            "findings_by_severity": {
                "Critical": len([f for f in findings_data if f["severity"] == "Critical"]),
                "High": len([f for f in findings_data if f["severity"] == "High"]),
                "Medium": len([f for f in findings_data if f["severity"] == "Medium"]),
                "Low": len([f for f in findings_data if f["severity"] == "Low"]),
                "Informational": len([f for f in findings_data if f["severity"] == "Informational"]),
                "Unknown": len([f for f in findings_data if f["severity"] == "Unknown"])
            },
            "risk_signals_recorded": state.risk_signals
        }

        # Attack Paths (Placeholder)
        attack_paths = [] # TODO: Implement logic to infer attack paths from executed_actions_log and findings

        # Limitations
        limitations = {
            "scope": state.scope_notes,
            "failed_actions_summary": len(state.failed_actions),
            "unexplored_assets": [a for a in state.known_assets if a not in state.asset_details and a not in state.blocked_assets]
        }
        
        # Executive Summary Inputs (High-level facts for a human-written summary)
        executive_summary_inputs = {
            "total_critical_findings": len([f for f in findings_data if f["severity"] == "Critical"]),
            "total_high_findings": len([f for f in findings_data if f["severity"] == "High"]),
            "total_assets_discovered": len(state.known_assets),
            "overall_assessment_outcome": report_meta["final_status"],
            "top_findings_summaries": [f["title"] for f in findings_data[:settings.LLM_RECENT_FINDINGS_COUNT]]
        }

        report_model = {
            "engagement_metadata": report_meta,
            "scope_definition": scope_definition,
            "methodology": methodology,
            "findings": findings_data,
            "risk_assessment": risk_assessment,
            "attack_paths": attack_paths,
            "limitations": limitations,
            "executive_summary_inputs": executive_summary_inputs
        }
        return report_model

    def generate_human_readable_report(self, report_data_model: Dict[str, Any], output_format: Literal["html", "markdown"] = "markdown") -> str:
        """
        Generates a human-readable report (e.g., Markdown or HTML).
        (Part 5: Output Modes)
        """
        # This is a placeholder for actual rendering logic
        if output_format == "markdown":
            report_str = f"# Penetration Test Report - {report_data_model['engagement_metadata']['initial_target']}

"
            report_str += f"## 1. Executive Summary
"
            report_str += f"Overall assessment outcome: {report_data_model['executive_summary_inputs']['overall_assessment_outcome']}.
"
            report_str += f"Discovered {report_data_model['executive_summary_inputs']['total_critical_findings']} Critical and {report_data_model['executive_summary_inputs']['total_high_findings']} High severity findings.

"
            
            report_str += f"## 2. Engagement Metadata
"
            for k, v in report_data_model['engagement_metadata'].items():
                report_str += f"- **{k.replace('_', ' ').title()}**: {v}
"
            report_str += f"
## 3. Scope Definition
"
            report_str += f"Primary Target: {report_data_model['scope_definition']['primary_target']}
"
            report_str += f"Known Assets: {', '.join(report_data_model['scope_definition']['known_assets'])}
"
            report_str += f"Discovered Subdomains: {', '.join(report_data_model['scope_definition']['discovered_subdomains'])}

"
            
            report_str += f"## 4. Methodology
"
            report_str += f"{report_data_model['methodology']['overview']}
"
            report_str += f"Total Actions Executed: {report_data_model['methodology']['total_actions']}
"
            for phase_name, phase_details in report_data_model['methodology']['phases'].items():
                report_str += f"### {phase_name.replace('_', ' ').title()}
"
                report_str += f"- Description: {phase_details['description']}
"
                report_str += f"- Tools Used: {', '.join(phase_details['tools_used'])}
"
                report_str += f"- Actions Count: {phase_details['actions_count']}
"
            report_str += "
"

            report_str += f"## 5. Findings ({len(report_data_model['findings'])})
"
            for finding in report_data_model['findings']:
                report_str += f"### {finding['id']}: {finding['title']}
"
                report_str += f"- **Severity**: {finding['severity']} (Score: {finding['severity_score']})
"
                report_str += f"- **Affected Asset**: {finding['affected_asset']}
"
                report_str += f"- **Description**: {finding['description']}
"
                report_str += f"- **Recommendation**: {finding['recommendation']}
"
                report_str += f"- **Proof of Concept**:
```
{finding['proof_of_concept']}
```
"
                report_str += f"- **Identified By**: {finding['tool_identified_by']} at {finding['timestamp']}

"
            
            report_str += f"## 6. Risk Assessment
"
            report_str += f"Overall Risk Score: {report_data_model['risk_assessment']['overall_risk_score']}
"
            report_str += f"Findings by Severity:
"
            for sev, count in report_data_model['risk_assessment']['findings_by_severity'].items():
                report_str += f"- {sev}: {count}
"
            report_str += "
"

            report_str += f"## 7. Limitations
"
            report_str += f"- Scope Notes: {report_data_model['limitations']['scope']}
"
            report_str += f"- Failed Actions: {report_data_model['limitations']['failed_actions_summary']} tool actions failed.
"
            report_str += f"- Unexplored Assets: {', '.join(report_data_model['limitations']['unexplored_assets'])}

"

            # TODO: Add Attack Paths
            
            return report_str
        elif output_format == "html":
            # Basic HTML structure (conceptual)
            html_content = "<html><head><title>Pentest Report</title></head><body>"
            html_content += f"<h1>Pentest Report - {report_data_model['engagement_metadata']['initial_target']}</h1>"
            # ... convert markdown to HTML or use a proper templating engine
            html_content += "</body></html>"
            return html_content
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def generate_machine_readable_report(self, report_data_model: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a machine-readable (JSON) report.
        (Part 5: Output Modes)
        """
        # The report_data_model itself is already machine-readable (JSON-serializable dict)
        return report_data_model

