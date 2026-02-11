from typing import Dict, Any, List, Optional
from agent.models import ToolResult, LLMAction # Assuming ToolResult model for processing results

class StateManager:
    """
    Manages the internal state of the security assessment.
    This includes targets, discovered assets, findings, pending tasks, etc.
    """
    def __init__(self):
        self._objective: str = ""
        self._initial_target: str = ""
        self._current_target: str = ""
        self._discovered_subdomains: List[str] = []
        self._known_targets: List[str] = [] # All targets identified for assessment
        self._findings: List[Dict[str, Any]] = [] # Discovered vulnerabilities/issues
        self._pending_tasks: Dict[str, LLMAction] = {} # task_id -> LLMAction that initiated it
        self._completed_tasks_results: List[ToolResult] = []
        self._is_objective_met: bool = False
        self._report: Optional[Dict[str, Any]] = None

    def initialize(self, objective: str, initial_target: str):
        """
        Initializes the state for a new assessment.
        """
        self._objective = objective
        self._initial_target = initial_target
        self._current_target = initial_target
        self._known_targets.append(initial_target)
        self._discovered_subdomains = []
        self._findings = []
        self._pending_tasks = {}
        self._completed_tasks_results = []
        self._is_objective_met = False
        self._report = None
        print(f"State initialized for objective: '{objective}' on target: '{initial_target}'")

    def get_current_state(self) -> Dict[str, Any]:
        """
        Returns a snapshot of the current relevant state for the LLM.
        """
        return {
            "objective": self._objective,
            "initial_target": self._initial_target,
            "current_target": self._current_target,
            "known_targets": list(set(self._known_targets)), # Unique targets
            "discovered_subdomains": list(set(self._discovered_subdomains)),
            "findings": self._findings,
            "pending_tasks_count": len(self._pending_tasks),
            "completed_tasks_count": len(self._completed_tasks_results),
            "is_objective_met": self._is_objective_met,
        }

    def add_pending_task(self, task_id: str, action: LLMAction):
        """
        Adds a task to the list of pending tasks.
        """
        self._pending_tasks[task_id] = action
        print(f"Added pending task: {task_id} (Tool: {action.action.tool_name if action.action.type == 'TOOL_EXECUTION' else action.action.type})")

    def process_tool_result(self, tool_result: ToolResult):
        """
        Processes the result of a completed tool execution.
        Updates the state based on the tool's output.
        """
        if tool_result.task_id in self._pending_tasks:
            del self._pending_tasks[tool_result.task_id]
            self._completed_tasks_results.append(tool_result)
            print(f"Processed completed task: {tool_result.task_id} (Status: {tool_result.status})")

            # Example: Update state based on subfinder results
            if tool_result.tool_name == "subfinder" and tool_result.status == "COMPLETED" and tool_result.output:
                new_subdomains = tool_result.output.get("subdomains", [])
                for subdomain in new_subdomains:
                    if subdomain not in self._discovered_subdomains:
                        self._discovered_subdomains.append(subdomain)
                        # Potentially add new subdomains to known_targets for further processing
                        if subdomain not in self._known_targets:
                            self._known_targets.append(subdomain)
                print(f"Discovered {len(new_subdomains)} new subdomains. Total: {len(self._discovered_subdomains)}")
            
            # Further logic to process other tool outputs (e.g., nmap, nuclei) would go here
            # and update _findings or _known_targets accordingly.

        else:
            print(f"Received result for unknown or already processed task: {tool_result.task_id}")

    def get_pending_tasks(self) -> Dict[str, LLMAction]:
        """
        Returns the dictionary of pending tasks.
        """
        return self._pending_tasks

    def update_internal_state(self, instruction: str):
        """
        Updates the internal state based on LLM's STATE_UPDATE instruction.
        This method would typically parse the instruction and apply changes.
        For now, it's a placeholder.
        """
        print(f"State update instruction from LLM: {instruction}")
        # In a real implementation, this would involve more sophisticated parsing
        # and modification of state attributes based on the instruction.
        # Example: if "move to next target", update _current_target.
        pass

    def mark_objective_met(self):
        """
        Marks the assessment objective as met.
        """
        self._is_objective_met = True
        print("Objective marked as met.")

    def is_objective_met(self) -> bool:
        """
        Checks if the assessment objective has been met.
        """
        return self._is_objective_met

    def save_report(self, report_data: Dict[str, Any]):
        """
        Saves the final report data.
        """
        self._report = report_data
        print("Final report saved.")

    def get_final_report(self) -> Optional[Dict[str, Any]]:
        """
        Returns the final report data.
        """
        return self._report
