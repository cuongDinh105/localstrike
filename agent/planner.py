import json
import time
from typing import Dict, Any, List, Optional

class Planner:
    """
    The 'brain' of the agent, responsible for orchestrating decision-making.
    It constructs prompts for the LLM based on the current state and overall objective.
    """
    def __init__(self):
        # Tools available to the LLM for planning.
        # This should ideally be dynamically fetched from MCP, but hardcoded for now.
        self.available_tools = [
            {"name": "subfinder", "description": "Performs subdomain enumeration for a given target.", "parameters": {"target": "string"}},
            {"name": "nmap", "description": "Performs port scanning and service detection.", "parameters": {"target": "string", "ports": "string", "flags": "string"}},
            # Add other tools as needed, defining their expected parameters for the LLM
        ]

    def create_llm_prompt(self, current_state: Dict[str, Any]) -> str:
        """
        Constructs the system and user prompts for the LLM based on the current state
        and the overall objective.
        """
        objective = current_state.get("objective", "Perform a security assessment.")
        current_target = current_state.get("current_target", "No target specified.")
        known_targets = current_state.get("known_targets", [])
        discovered_subdomains = current_state.get("discovered_subdomains", [])
        findings = current_state.get("findings", [])
        pending_tasks_count = current_state.get("pending_tasks_count", 0)

        # System prompt instructions
        system_prompt = (
            "You are an AI penetration testing agent. Your goal is to achieve the objective by "
            "planning and making decisions based on the current assessment state. "
            "You can choose to execute security tools via the HexStrike MCP, update the internal state, "
            "or generate a final report. "
            "You MUST output a JSON object strictly conforming to the `LLMAction` schema.
"
            "Here are the tools available through HexStrike MCP:
"
        )
        for tool in self.available_tools:
            system_prompt += f"- Tool: {tool['name']}, Description: {tool['description']}, Parameters: {json.dumps(tool['parameters'])}
"
        
        system_prompt += (
            "
Based on the current state and the objective, decide the next best action. "
            "Prioritize actions that move towards the objective efficiently. "
            "If there are pending tasks, consider waiting for their results before initiating new, dependent actions."
        )

        # User prompt - providing the current state
        user_prompt = (
            f"Current Objective: {objective}
"
            f"Initial Target: {current_state.get('initial_target')}
"
            f"Current Focus Target: {current_target}
"
            f"Known Targets for Assessment: {', '.join(known_targets) if known_targets else 'None'}
"
            f"Discovered Subdomains: {', '.join(discovered_subdomains) if discovered_subdomains else 'None'}
"
            f"Current Findings: {json.dumps(findings, indent=2)}
"
            f"Pending Tasks: {pending_tasks_count}

"
            "What is the next logical step to achieve the objective? "
            "Provide your thought process and the chosen action in the specified JSON format."
        )

        return system_prompt, user_prompt # Return both parts of the prompt

    def generate_final_report(self, final_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a summary report based on the final assessment state.
        This is a placeholder and would involve more sophisticated report generation.
        """
        print("Generating final report...")
        report_data = {
            "title": f"LocalStrike Security Assessment Report for {final_state.get('initial_target')}",
            "objective": final_state.get("objective"),
            "initial_target": final_state.get("initial_target"),
            "known_targets_assessed": final_state.get("known_targets"),
            "discovered_subdomains": final_state.get("discovered_subdomains"),
            "findings": final_state.get("findings"),
            "summary": "This is a placeholder report summary. Detailed findings and recommendations would be included here.",
            "status": "Completed" if final_state.get("is_objective_met") else "Partial",
            "timestamp": time.time() # This will cause an error due to time not being imported. I should fix this.
        }
        return report_data
