"""
state/manager.py: Manages the internal state of the LocalStrike AI agent's assessment.
"""

import logging
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple

from schemas.action import LLMInternalAction, ToolResult, ToolOutput, ToolMetadata, ExecutedAction, ReviewerFeedback, AssetNode, AssetRelationship # Updated import
from config.settings import settings
from reporting.engine import ReportEngine # Import the ReportEngine
from asset_graph.engine import AssetGraphEngine # Import AssetGraphEngine
from scope.engine import ScopeDefinition # Import ScopeDefinition to pass to AssetGraphEngine

logger = logging.getLogger(__name__)

class StateManager:
    """
    Manages the internal state of the security assessment, integrating:
    - Core state model categories
    - LLM memory visibility rules
    - Memory summarization system
    - Loop control & termination logic
    - Safety, traceability & audit
    """
    _STATE_FILE = "assessment_state.json" # TODO: Make dynamic or configurable per assessment

    def __init__(self, state_dir: str = "./state_data"): # TODO: Make state_dir configurable
        self._state_dir = state_dir
        # Ensure state directory exists
        import os
        os.makedirs(self._state_dir, exist_ok=True)
        self._state_file_path = os.path.join(self._state_dir, self._STATE_FILE)

        # Core State Model
        # 1. Objective & Scope
        self.objective: str = ""
        self.initial_target: str = ""
        self.scope_notes: str = ""
        self.start_time: Optional[datetime] = None
        self.max_iterations: int = settings.MAX_AGENT_ITERATIONS
        self.max_runtime: timedelta = timedelta(seconds=settings.MAX_AGENT_RUNTIME_SECONDS)

        # 2. Asset Discovery (now managed by AssetGraphEngine)
        # self.known_assets: Set[str] = set() # Replaced by asset_graph_engine.asset_nodes
        self.discovered_subdomains: Set[str] = set() # Still useful for quick summarization
        self.discovered_ips: Set[str] = set() # Still useful for quick summarization

        # 3. Attack Surface Mapping (detailed info per asset)
        self.asset_details: Dict[str, Dict[str, Any]] = {} # asset -> {ports: Set[int], services: List[Dict], technologies: List[str]}
        self.current_focus_asset: Optional[str] = None # Asset LLM is currently focused on

        # 4. Findings & Evidence
        self.findings: List[Dict[str, Any]] = [] # Each finding is a dict, includes raw_output_ref (hash)
        self.raw_evidence_store: Dict[str, str] = {} # hash -> raw_tool_output (machine-only visibility)

        # 5. Executed Actions (for audit, replay, loop control)
        self.executed_actions_log: List[ExecutedAction] = [] # Full log of ExecutedAction
        self.current_iteration: int = 0

        # 6. Pending Tasks (MCP task_id -> (LLMInternalAction, action_id))
        self.pending_mcp_tasks: Dict[str, Tuple[LLMInternalAction, str]] = {}

        # 7. Failed / Blocked Actions
        self.failed_actions: Dict[Tuple[str, str], int] = {} # (tool_name, target) -> failure_count
        self.blocked_assets: Set[str] = set() # Assets that are unresponsive or constantly fail

        # 8. Risk Signals
        self.risk_signals: List[Dict[str, Any]] = []

        # 9. Termination Conditions & Loop Control
        self.objective_met: bool = False
        self.force_terminate: bool = False
        self.no_progress_count: int = 0
        self.last_progress_update: datetime = datetime.now()
        self.repeated_action_sequences: List[Tuple[str, ...]] = [] # Track N recent action types for repetition detection
        self._action_history_for_repetition: List[str] = [] # Short-term history of tool_name/command for repetition

        self.final_report_data: Optional[Dict[str, Any]] = None

        # This will be set by the agent, needed for ReportEngine
        self.tool_metadata_map: Dict[str, ToolMetadata] = {} 

        # Asset Graph Engine
        self.asset_graph_engine: Optional[AssetGraphEngine] = None
        # Scope Definition (will be initialized in initialize)
        self.scope_definition: Optional[ScopeDefinition] = None

        logger.info("StateManager initialized.")
        self._load_state() # Attempt to load previous state on init

    def _hash_content(self, content: str) -> str:
        """Hashes content for evidence integrity and deduplication."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def _save_state(self):
        """Persists the current state to disk."""
        try:
            # Convert sets to lists for JSON serialization
            state_to_save = {
                "objective": self.objective,
                "initial_target": self.initial_target,
                "scope_notes": self.scope_notes,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "max_iterations": self.max_iterations,
                "max_runtime_seconds": self.max_runtime.total_seconds(),

                # "known_assets": list(self.known_assets), # Managed by asset_graph_engine
                "discovered_subdomains": list(self.discovered_subdomains),
                "discovered_ips": list(self.discovered_ips),

                "asset_details": {k: {key: list(v) if isinstance(v, set) else v for key, v in val.items()}
                                  for k, val in self.asset_details.items()},
                "current_focus_asset": self.current_focus_asset,

                "findings": self.findings,
                "raw_evidence_store": self.raw_evidence_store,

                "executed_actions_log": [entry.model_dump_json() for entry in self.executed_actions_log], # Serialize ExecutedAction
                "current_iteration": self.current_iteration,

                "pending_mcp_tasks": {k: (v[0].model_dump_json(), v[1]) for k, v in self.pending_mcp_tasks.items()}, # Store tuple
                
                "failed_actions": {str(k): v for k, v in self.failed_actions.items()}, # Convert tuple key to string
                "blocked_assets": list(self.blocked_assets),

                "risk_signals": self.risk_signals,

                "objective_met": self.objective_met,
                "force_terminate": self.force_terminate,
                "no_progress_count": self.no_progress_count,
                "last_progress_update": self.last_progress_update.isoformat(),
                "repeated_action_sequences": [list(s) for s in self.repeated_action_sequences], # Store as list of lists
                "_action_history_for_repetition": self._action_history_for_repetition,

                "final_report_data": self.final_report_data,
                "tool_metadata_map": {k: v.model_dump_json() for k, v in self.tool_metadata_map.items()}, # Save tool metadata
                
                "asset_graph_engine": { # Serialize AssetGraphEngine's state
                    "asset_nodes": {aid: node.model_dump_json() for aid, node in self.asset_graph_engine.asset_nodes.items()} if self.asset_graph_engine else {},
                    "relationships": {aid: [rel.model_dump_json() for rel in rels] for aid, rels in self.asset_graph_engine.relationships.items()} if self.asset_graph_engine else {}
                },
                "scope_definition": self.scope_definition.model_dump_json() if self.scope_definition else None
            }
            with open(self._state_file_path, 'w') as f:
                json.dump(state_to_save, f, indent=2)
            logger.debug(f"State saved to {self._state_file_path}")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def _load_state(self):
        """Loads state from disk if available."""
        try:
            if os.path.exists(self._state_file_path):
                with open(self._state_file_path, 'r') as f:
                    loaded_state = json.load(f)
                
                self.objective = loaded_state.get("objective", "")
                self.initial_target = loaded_state.get("initial_target", "")
                self.scope_notes = loaded_state.get("scope_notes", "")
                self.start_time = datetime.fromisoformat(loaded_state["start_time"]) if loaded_state.get("start_time") else None
                self.max_iterations = loaded_state.get("max_iterations", settings.MAX_AGENT_ITERATIONS)
                self.max_runtime = timedelta(seconds=loaded_state.get("max_runtime_seconds", settings.MAX_AGENT_RUNTIME_SECONDS))

                # self.known_assets = set(loaded_state.get("known_assets", [])) # Managed by asset_graph_engine
                self.discovered_subdomains = set(loaded_state.get("discovered_subdomains", []))
                self.discovered_ips = set(loaded_state.get("discovered_ips", []))

                self.asset_details = {k: {key: set(v) if key == 'ports' else v for key, v in val.items()} # Convert ports back to set
                                      for k, val in loaded_state.get("asset_details", {}).items()}
                self.current_focus_asset = loaded_state.get("current_focus_asset", None)

                self.findings = loaded_state.get("findings", [])
                self.raw_evidence_store = loaded_state.get("raw_evidence_store", {})

                self.executed_actions_log = [ExecutedAction.model_validate_json(entry) for entry in loaded_state.get("executed_actions_log", [])] # Deserialize ExecutedAction
                self.current_iteration = loaded_state.get("current_iteration", 0)

                self.pending_mcp_tasks = {k: (LLMInternalAction.model_validate_json(v[0]), v[1]) for k, v in loaded_state.get("pending_mcp_tasks", {}).items()} # Load tuple
                
                self.failed_actions = {eval(k): v for k, v in loaded_state.get("failed_actions", {}).items()} # Convert string key back to tuple
                self.blocked_assets = set(loaded_state.get("blocked_assets", []))

                self.risk_signals = loaded_state.get("risk_signals", [])

                self.objective_met = loaded_state.get("objective_met", False)
                self.force_terminate = loaded_state.get("force_terminate", False)
                self.no_progress_count = loaded_state.get("no_progress_count", 0)
                self.last_progress_update = datetime.fromisoformat(loaded_state["last_progress_update"]) if loaded_state.get("last_progress_update") else datetime.now()
                self.repeated_action_sequences = [tuple(s) for s in loaded_state.get("repeated_action_sequences", [])]
                self._action_history_for_repetition = loaded_state.get("_action_history_for_repetition", [])

                self.final_report_data = loaded_state.get("final_report_data", None)
                self.tool_metadata_map = {k: ToolMetadata.model_validate_json(v) for k, v in loaded_state.get("tool_metadata_map", {}).items()}

                # Load AssetGraphEngine state
                if loaded_state.get("scope_definition"):
                    self.scope_definition = ScopeDefinition.model_validate_json(loaded_state["scope_definition"])
                else:
                    logger.warning("No scope_definition found in loaded state. AssetGraphEngine might not be fully initialized.")
                    # TODO: handle re-initialization of scope_definition/asset_graph_engine if needed

                if self.scope_definition:
                    self.asset_graph_engine = AssetGraphEngine(self.scope_definition) # Pass scope_definition
                    loaded_nodes = {aid: AssetNode.model_validate_json(node_json) for aid, node_json in loaded_state.get("asset_graph_engine", {}).get("asset_nodes", {}).items()}
                    loaded_relationships = {aid: [AssetRelationship.model_validate_json(rel_json) for rel_json in rel_jsons] for aid, rel_jsons in loaded_state.get("asset_graph_engine", {}).get("relationships", {}).items()}
                    self.asset_graph_engine.asset_nodes = loaded_nodes
                    self.asset_graph_engine.relationships = loaded_relationships


                logger.info(f"State loaded from {self._state_file_path}. Current iteration: {self.current_iteration}")
            else:
                logger.info("No saved state found, starting fresh.")
        except Exception as e:
            logger.error(f"Failed to load state: {e}. Starting fresh.")
            self._reset_state_on_error() # Reset state to avoid corrupted data

    def _reset_state_on_error(self):
        """Resets relevant state attributes if loading fails."""
        self.objective = ""
        self.initial_target = ""
        self.scope_notes = ""
        self.start_time = None
        self.current_iteration = 0
        # self.known_assets = set() # Replaced by asset_graph_engine
        self.discovered_subdomains = set()
        self.discovered_ips = set()
        self.asset_details = {}
        self.current_focus_asset = None
        self.findings = []
        self.raw_evidence_store = {}
        self.executed_actions_log = []
        self.pending_mcp_tasks = {}
        self.failed_actions = {}
        self.blocked_assets = set()
        self.risk_signals = []
        self.objective_met = False
        self.force_terminate = False
        self.no_progress_count = 0
        self.last_progress_update = datetime.now()
        self.repeated_action_sequences = []
        self._action_history_for_repetition = []
        self.final_report_data = None
        self.tool_metadata_map = {}
        self.asset_graph_engine = None
        self.scope_definition = None

    def initialize(self, objective: str, initial_target: str, scope_notes: str = "", scope_definition: Optional[ScopeDefinition] = None):
        """
        Initializes or re-initializes the state for a new assessment.
        If state was loaded, this might override some values.
        """
        if not self.start_time: # Only set on first init
            self.start_time = datetime.now()
        self.objective = objective
        self.initial_target = initial_target
        self.scope_notes = scope_notes
        # self.known_assets.add(initial_target) # Managed by asset_graph_engine

        # Initialize ScopeDefinition and AssetGraphEngine
        if scope_definition:
            self.scope_definition = scope_definition
        elif not self.scope_definition: # If not passed and not loaded
            # Create a default scope definition for now
            self.scope_definition = ScopeDefinition(
                initial_target_value=initial_target,
                allowed_domains=[initial_target] if '.' in initial_target else [], # Simple heuristic
                allowed_ip_ranges=[initial_target + "/32"] if '.' not in initial_target else [], # Simple heuristic
                max_depth=settings.DEFAULT_SCOPE_MAX_DEPTH
            )

        if not self.asset_graph_engine:
            self.asset_graph_engine = AssetGraphEngine(self.scope_definition)
        else: # Re-initialize with new scope if already exists
            self.asset_graph_engine.scope_definition = self.scope_definition
            self.asset_graph_engine.asset_nodes = {}
            self.asset_graph_engine.relationships = {}

        # Add initial target to asset graph
        initial_target_type = self.asset_graph_engine._infer_asset_type(initial_target)
        initial_node = self.asset_graph_engine.add_asset(
            asset_type=initial_target_type,
            value=initial_target,
            discovery_source_action_id="initial_config",
            in_scope=True # Initial target is always in scope
        )
        self.current_focus_asset = initial_node.asset_id # Focus on the ID

        self.objective_met = False
        self.force_terminate = False
        self.current_iteration = 0
        self.no_progress_count = 0
        self.last_progress_update = datetime.now()
        self._action_history_for_repetition = []
        self.executed_actions_log = [] # Clear action log for new assessment
        self.findings = [] # Clear findings
        self.raw_evidence_store = {} # Clear raw evidence
        self.pending_mcp_tasks = {} # Clear pending tasks
        # tool_metadata_map is usually loaded once by agent, not cleared here

        self._save_state()
        logger.info(f"State initialized for objective: '{objective}' on target: '{initial_target}' with scope {self.scope_definition.model_dump_json()}")

    def _update_progress(self):
        """Resets no_progress_count and updates last_progress_update."""
        self.no_progress_count = 0
        self.last_progress_update = datetime.now()

    def add_executed_action(self, 
                            llm_internal_action: LLMInternalAction, 
                            status: str = "PROPOSED", 
                            error: Optional[str] = None,
                            reviewer_feedback: Optional[ReviewerFeedback] = None, # New parameter
                            scope_validation_result: Optional[SemanticValidationResult] = None # New parameter
                            ) -> str:
        """Records an action proposed by LLM and its lifecycle. Returns the action_id."""
        action_id = hashlib.sha256(f"{llm_internal_action.model_dump_json()}:{datetime.now().isoformat()}".encode()).hexdigest() # Unique ID

        action_entry = ExecutedAction( # Use the Pydantic model
            action_id=action_id, 
            llm_internal_action=llm_internal_action,
            status=status,
            error_message=error,
            start_time=datetime.now(),
            reviewer_feedback=reviewer_feedback, # Store reviewer feedback
            scope_validation_result=scope_validation_result # Store scope validation result
        )
        self.executed_actions_log.append(action_entry)
        self.current_iteration += 1
        
        # Update short-term action history for repetition detection
        self._action_history_for_repetition.append(llm_internal_action.action.tool_name if llm_internal_action.action.type == "TOOL_EXECUTION" else llm_internal_action.action.type)
        if len(self._action_history_for_repetition) > settings.REPETITION_HISTORY_LENGTH:
            self._action_history_for_repetition.pop(0)

        # Check for repetition and dead-ends
        self._check_for_repetition()
        self._save_state()
        logger.debug(f"Action logged: {llm_internal_action.action.tool_name if llm_internal_action.action.type == 'TOOL_EXECUTION' else llm_internal_action.action.type}")
        return action_id # Return action_id for later updates

    def update_executed_action_status(self, 
                                      action_id: str, 
                                      status: str, 
                                      error: Optional[str] = None, 
                                      mcp_task_id: Optional[str] = None,
                                      human_decision_time: Optional[datetime] = None, # New
                                      human_decision_id: Optional[str] = None, # New
                                      modified_parameters: Optional[Dict[str, Any]] = None # New
                                      ):
        """Updates the status and other details of a previously logged action."""
        for entry in reversed(self.executed_actions_log): # Search recent entries first
            if entry.action_id == action_id:
                entry.status = status
                entry.end_time = datetime.now()
                if error:
                    entry.error_message = error
                if mcp_task_id:
                    entry.mcp_task_id = mcp_task_id
                if human_decision_time:
                    entry.human_decision_time = human_decision_time
                if human_decision_id:
                    entry.human_decision_id = human_decision_id
                if modified_parameters:
                    entry.modified_parameters = modified_parameters
                self._save_state()
                logger.debug(f"Action '{action_id}' status updated to '{status}'.")
                return
        logger.warning(f"Could not find executed action with ID '{action_id}' to update.")
        self._save_state()


    def _check_for_repetition(self):
        """Detects if a sequence of actions is repeating."""
        history_len = len(self._action_history_for_repetition)
        if history_len < settings.REPETITION_HISTORY_LENGTH:
            return

        # Check for simple immediate repetition (e.g., tool_A, tool_A)
        if history_len >= 2 and self._action_history_for_repetition[-1] == self._action_history_for_repetition[-2]:
            self.risk_signals.append({"type": "IMMEDIATE_REPETITION", "description": f"Tool '{self._action_history_for_repetition[-1]}' repeated immediately.", "timestamp": datetime.now().isoformat()})
            self.no_progress_count += 1
            logger.warning(f"Immediate action repetition detected: {self._action_history_for_repetition[-1]}")
            return

        # Check for longer sequence repetition (e.g., A,B,C,A,B,C)
        for length in range(settings.REPETITION_MIN_SEQUENCE_LENGTH, history_len // 2 + 1):
            sequence = tuple(self._action_history_for_repetition[-length:])
            previous_sequence = tuple(self._action_history_for_repetition[-(2 * length):-length])
            
            if sequence == previous_sequence:
                if sequence not in self.repeated_action_sequences:
                    self.repeated_action_sequences.append(sequence)
                    self.risk_signals.append({"type": "SEQUENCE_REPETITION", "description": f"Action sequence '{sequence}' repeated.", "timestamp": datetime.now().isoformat()})
                    self.no_progress_count += settings.REPETITION_SEQUENCE_PENALTY
                    logger.warning(f"Repeated action sequence detected: {sequence}")
                break # Found a repetition, no need to check shorter sequences

    def add_pending_mcp_task(self, task_id: str, action: LLMInternalAction, action_id: str):
        """Adds a task to the list of pending MCP tasks."""
        self.pending_mcp_tasks[task_id] = (action, action_id)
        logger.debug(f"Added pending MCP task: {task_id} (Tool: {action.action.tool_name if action.action.type == 'TOOL_EXECUTION' else action.action.type}) linked to action ID: {action_id}")
        self._save_state()

    def process_tool_result(self, tool_result: ToolResult):
        """
        Processes the result of a completed MCP tool execution.
        Updates the assessment state based on the tool's output and action log.
        """
        pending_tuple = self.pending_mcp_tasks.pop(tool_result.task_id, None)
        if not pending_tuple:
            logger.warning(f"Received result for unknown or already processed task: {tool_result.task_id}. Skipping.")
            return

        original_llm_action, action_id_for_log = pending_tuple

        # Find the executed action log entry and update its final status
        found_and_updated = False
        for entry in reversed(self.executed_actions_log):
            if entry.action_id == action_id_for_log: # Use the stored action_id
                entry.status = tool_result.status
                entry.end_time = datetime.now()
                if tool_result.error:
                    entry.error_message = tool_result.error.message
                # entry.mcp_task_id is already set at EXECUTING stage
                found_and_updated = True
                break
        if not found_and_updated:
            logger.warning(f"Could not find matching executed action for task_id {tool_result.task_id} and action_id {action_id_for_log} in log for final update.")

        if tool_result.status == "COMPLETED" and tool_result.output:
            self._process_tool_output_for_state(tool_result.tool_name, tool_result.output, original_llm_action.action.parameters.get("target"), original_llm_action.action.reason)
            self._update_progress() # Progress made
        elif tool_result.status == "FAILED":
            tool_target = original_llm_action.action.parameters.get("target", "unknown")
            self.failed_actions[(original_llm_action.action.tool_name, tool_target)] = self.failed_actions.get((original_llm_action.action.tool_name, tool_target), 0) + 1
            if self.failed_actions[(original_llm_action.action.tool_name, tool_target)] >= settings.TOOL_FAILURE_THRESHOLD:
                self.blocked_assets.add(tool_target)
                self.risk_signals.append({"type": "BLOCKED_ASSET", "description": f"Asset '{tool_target}' appears blocked for tool '{original_llm_action.action.tool_name}'.", "timestamp": datetime.now().isoformat()})
                logger.error(f"Asset '{tool_target}' blocked due to repeated failures with '{original_llm_action.action.tool_name}'.")
            
            logger.error(f"Task {tool_result.task_id} for tool {original_llm_action.action.tool_name} failed. Error: {tool_result.error.message if tool_result.error else 'Unknown'}")
            self.no_progress_count += settings.FAILURE_PENALTY # Penalty for failed actions

        self._save_state()
        logger.info(f"Processed completed task: {tool_result.task_id} (Tool: {tool_result.tool_name}, Status: {tool_result.status})")

    def _process_tool_output_for_state(self, tool_name: str, output: ToolOutput, target: Optional[str], original_reason: str): # Changed output type to ToolOutput and added original_reason
        """
        Parses tool output and updates relevant state categories (asset discovery, attack surface, findings).
        """
        new_data_found = False

        # Store raw output in evidence store (machine-only visibility)
        if output.raw_output_ref and output.raw_output_ref not in self.raw_evidence_store:
            # TODO: The actual raw content needs to be fetched from MCP by this ref
            # For now, we'll just store the ref.
            self.raw_evidence_store[output.raw_output_ref] = f"Refers to raw output for tool {tool_name} task {output.raw_output_ref}"
            logger.debug(f"Raw output ref stored: {output.raw_output_ref}")

        # Process assets found
        for asset_value in output.assets_found:
            inferred_type = self.asset_graph_engine._infer_asset_type(asset_value) # Use asset_graph_engine to infer type
            asset_id = AssetNode.generate_asset_id(inferred_type, asset_value)
            
            # Add asset to graph if not exists
            if asset_id not in self.asset_graph_engine.asset_nodes:
                # Determine parent asset ID and scope status for the new asset
                parent_asset_id = None
                if target:
                    target_type = self.asset_graph_engine._infer_asset_type(target)
                    parent_asset_id = AssetNode.generate_asset_id(target_type, target)

                # Check if newly discovered asset is in scope based on semantic rules
                semantic_validation = self.asset_graph_engine.semantic_validate_target(
                    asset_value, 
                    # State snapshot not directly available here, pass initial target and known_assets
                    {"initial_target": self.initial_target, "known_assets": list(self.asset_graph_engine.asset_nodes.keys())},
                    discovery_action_id=None # Not direct discovery action, but target of discovery
                )
                
                is_in_scope = semantic_validation.is_valid # Use semantic validation result

                new_node = self.asset_graph_engine.add_asset(
                    asset_type=inferred_type,
                    value=asset_value,
                    parent_asset_id=parent_asset_id, # Link to the target of the current tool execution
                    discovery_source_action_id=self.executed_actions_log[-1].action_id if self.executed_actions_log else None, # Link to last executed action
                    in_scope=is_in_scope
                )
                if parent_asset_id:
                    self.asset_graph_engine.add_relationship(
                        source_asset_id=parent_asset_id,
                        target_asset_id=new_node.asset_id,
                        relationship_type="discovered_from" # Generic discovery relationship
                    )

                # Update existing summary sets for LLM-visible state
                if "domain" in inferred_type:
                    self.discovered_subdomains.add(asset_value)
                elif inferred_type == "ip":
                    self.discovered_ips.add(asset_value)
                
                new_data_found = True
        if new_data_found: logger.debug(f"Added {len(output.assets_found)} new assets to graph.")
        
        # Process findings
        for finding_data in output.findings:
            # Assuming finding_data contains {severity, description, etc.}
            finding_content_hash = self._hash_content(json.dumps(finding_data, sort_keys=True))
            # Check for duplicate findings using hash of content
            is_duplicate = False
            for existing_finding in self.findings:
                if self._hash_content(json.dumps(existing_finding, sort_keys=True)) == finding_content_hash:
                    is_duplicate = True
                    break

            if not is_duplicate:
                finding_entry = {
                    "finding_id": f"FIN-{len(self.findings)+1}-{finding_content_hash[:4]}",
                    "severity": finding_data.get("severity", "UNKNOWN"),
                    "description": finding_data.get("description", "No description"),
                    "affected_asset": target if target else "N/A", # Link to asset if possible
                    "tool_name": tool_name,
                    "raw_output_ref": output.raw_output_ref,
                    "timestamp": datetime.now().isoformat()
                }
                self.findings.append(finding_entry)
                new_data_found = True
                logger.info(f"New finding added: {finding_entry['description']}")
        
        # Process metrics (e.g., for attack surface mapping)
        # TODO: Integrate metrics into asset_details if applicable
        
        if new_data_found:
            self._update_progress()
        self._save_state()

    def get_pending_mcp_tasks(self) -> Dict[str, Tuple[LLMInternalAction, str]]:
        """Returns the dictionary of currently pending MCP tasks."""
        return self.pending_mcp_tasks

    def update_internal_state(self, instruction: str, parameters: Dict[str, Any]):
        """
        Updates the internal state based on LLM's STATE_UPDATE instruction.
        This method parses the instruction and applies changes to state attributes.
        """
        logger.info(f"Received LLM instruction to update state: '{instruction}' with parameters: {parameters}")
        
        # Example parsing of instruction/parameters
        if "focus_asset" in parameters:
            new_focus_value = str(parameters["focus_asset"])
            # Check if this asset exists in graph and is in scope
            new_focus_id = AssetNode.generate_asset_id(self.asset_graph_engine._infer_asset_type(new_focus_value), new_focus_value)
            if new_focus_id in self.asset_graph_engine.asset_nodes and self.asset_graph_engine.asset_nodes[new_focus_id].in_scope:
                self.current_focus_asset = new_focus_id
                self._update_progress() # Considered progress if focus shifts
                logger.info(f"Agent focus shifted to: {self.asset_graph_engine.asset_nodes[new_focus_id].value}")
            else:
                logger.warning(f"LLM tried to focus on unknown or out-of-scope asset: {new_focus_value}")
        
        if "ignore_asset" in parameters:
            asset_to_ignore_value = str(parameters["ignore_asset"])
            asset_to_ignore_id = AssetNode.generate_asset_id(self.asset_graph_engine._infer_asset_type(asset_to_ignore_value), asset_to_ignore_value)
            if asset_to_ignore_id in self.asset_graph_engine.asset_nodes:
                self.blocked_assets.add(asset_to_ignore_value) # Block by value for now
                self.risk_signals.append({"type": "MANUAL_BLOCK", "description": f"Asset '{asset_to_ignore_value}' manually blocked by LLM instruction.", "timestamp": datetime.now().isoformat()})
                logger.info(f"Asset '{asset_to_ignore_value}' added to blocked list.")
        
        # TODO: Implement more sophisticated parsing for state updates
        self._save_state()

    def _get_llm_visible_asset_details(self, asset_id: str) -> Dict[str, Any]:
        """Helper to get summarized asset details for LLM."""
        asset_value = self.asset_graph_engine.asset_nodes[asset_id].value if asset_id in self.asset_graph_engine.asset_nodes else "UNKNOWN"
        details = self.asset_details.get(asset_value, {}) # asset_details still indexed by value
        summary = {}
        if details.get("ports"):
            summary["open_ports_count"] = len(details["ports"])
            summary["example_ports"] = sorted(list(details["ports"]))[:settings.LLM_EXAMPLE_PORTS_COUNT]
        if details.get("services"):
            summary["services_count"] = len(details["services"])
            unique_services = list(set([s.get("name") for s in details["services"] if s.get("name")]))
            summary["example_services"] = unique_services[:settings.LLM_EXAMPLE_SERVICES_COUNT]
        if details.get("technologies"):
            summary["technologies"] = details["technologies"][:settings.LLM_EXAMPLE_TECH_COUNT]
        return summary

    def _get_llm_visible_executed_actions_summary(self) -> str:
        """Summarizes executed actions for LLM context."""
        total_actions = len(self.executed_actions_log)
        if total_actions == 0:
            return "No actions executed yet."
        
        recent_actions = self.executed_actions_log[-settings.LLM_RECENT_ACTIONS_COUNT:]
        summary_lines = [f"Total actions executed: {total_actions}."]
        summary_lines.append("Recent actions (last 5):")
        for action_entry in recent_actions:
            action_type = action_entry.llm_internal_action.action.type
            tool_name = action_entry.llm_internal_action.action.tool_name if action_type == "TOOL_EXECUTION" else action_type
            status = action_entry.status
            summary_lines.append(f"- {action_type} ({tool_name}) - {status} at {action_entry.start_time.isoformat()}")
        
        if self.repeated_action_sequences:
            summary_lines.append("WARNING: Detected repeated action sequences:")
            for seq in self.repeated_action_sequences:
                summary_lines.append(f"  - {seq}")
        return "\n".join(summary_lines)

    def _get_llm_visible_findings_summary(self) -> str:
        """Summarizes findings for LLM context, prioritizing high severity."""
        if not self.findings:
            return "No findings identified yet."
        
        high_sev_findings = [f for f in self.findings if f.get("severity", "UNKNOWN") in ["CRITICAL", "HIGH"]]
        summary_lines = [f"Total findings identified: {len(self.findings)}."]
        if high_sev_findings:
            summary_lines.append(f"High/Critical findings: {len(high_sev_findings)} (see below for details).")
        
        # Always include new/high-severity findings verbatim
        for finding in high_sev_findings[-settings.LLM_RECENT_FINDINGS_COUNT:]:
            summary_lines.append(f"- Finding ID: {finding['finding_id']}, Severity: {finding['severity']}, Asset: {finding['affected_asset']}, Desc: {finding['description']}. (Raw evidence ref: {finding['raw_output_ref']})")
        
        # Add summary of other findings if many
        if len(self.findings) > settings.LLM_RECENT_FINDINGS_COUNT and not high_sev_findings:
            summary_lines.append(f"Summary of {len(self.findings) - settings.LLM_RECENT_FINDINGS_COUNT} older findings available in full report.")
        
        return "\n".join(summary_lines)

    def get_llm_visible_state(self) -> Dict[str, Any]:
        """
        Constructs a summarized, LLM-visible snapshot of the current state.
        This method applies visibility rules and summarization.
        """
        llm_state = {
            "objective": self.objective,
            "initial_target": self.initial_target,
            "current_focus_asset": self.asset_graph_engine.asset_nodes.get(self.current_focus_asset).value if self.current_focus_asset else None, # Display asset value
            "scope_notes": self.scope_notes,
            "status_update": "Assessment in progress.",
            "termination_signals": {}
        }

        # Asset Discovery summary
        llm_state["known_assets_summary"] = {
            "total_count": len(self.asset_graph_engine.asset_nodes),
            "in_scope_assets_count": len([n for n in self.asset_graph_engine.asset_nodes.values() if n.in_scope]),
            "example_in_scope_assets": [n.value for n in list(self.asset_graph_engine.asset_nodes.values()) if n.in_scope][:settings.LLM_EXAMPLE_ASSETS_COUNT],
            "discovered_subdomains_count": len(self.discovered_subdomains),
            "discovered_ips_count": len(self.discovered_ips)
        }

        # Attack Surface Mapping for current focus asset
        if self.current_focus_asset:
            llm_state["current_focus_asset_details"] = self._get_llm_visible_asset_details(self.current_focus_asset)
        
        # Findings summary
        llm_state["findings_summary"] = self._get_llm_visible_findings_summary()

        # Executed Actions summary
        llm_state["actions_summary"] = self._get_llm_visible_executed_actions_summary()

        # Pending tasks count
        llm_state["pending_tasks_count"] = len(self.pending_mcp_tasks)

        # Failed/Blocked actions & Risk Signals
        if self.blocked_assets: # blocked_assets still uses value for now
            llm_state["termination_signals"]["blocked_assets"] = list(self.blocked_assets)
        if self.failed_actions:
            llm_state["termination_signals"]["recent_failed_tools"] = {str(k): v for k, v in self.failed_actions.items() if v >= settings.LLM_FAILED_ACTION_THRESHOLD}
        if self.risk_signals:
            llm_state["termination_signals"]["risk_signals"] = self.risk_signals[-settings.LLM_RECENT_RISK_SIGNALS_COUNT:]
        
        # Termination conditions (soft signals for LLM)
        if self.current_iteration >= self.max_iterations * 0.8:
            llm_state["termination_signals"]["max_iterations_approaching"] = f"Reached {self.current_iteration}/{self.max_iterations} iterations."
        if (datetime.now() - self.start_time) >= self.max_runtime * 0.8:
            llm_state["termination_signals"]["max_runtime_approaching"] = f"Remaining time: {self.max_runtime - (datetime.now() - self.start_time)}."
        if self.no_progress_count >= settings.NO_PROGRESS_THRESHOLD:
            llm_state["termination_signals"]["no_progress_detected"] = f"No significant progress for {self.no_progress_count} iterations."
        
        return llm_state

    def is_objective_met(self) -> bool:
        """
        Checks if the assessment objective has been met based on various termination conditions.
        This implements Part 4 - Loop Control & Termination Logic.
        """
        if self.objective_met: # Set by LLM explicitly via ReportGenerationAction
            logger.info("Objective met (LLM signaled completion).")
            return True
        if self.force_terminate: # Set externally or by hard error
            logger.warning("Objective met (force terminate signaled).")
            return True
        if self.current_iteration >= self.max_iterations:
            logger.warning(f"Hard stop: Max iterations ({self.max_iterations}) reached.")
            self.objective_met = True
            return True
        if (datetime.now() - self.start_time) >= self.max_runtime:
            logger.warning(f"Hard stop: Max runtime ({self.max_runtime}) reached.")
            self.objective_met = True
            return True
        if self.no_progress_count >= settings.MAX_NO_PROGRESS_COUNT:
            logger.warning(f"Hard stop: No significant progress for {self.no_progress_count} iterations.")
            self.objective_met = True
            return True
        
        # Dead-end detection: If all known_assets are blocked AND no pending tasks
        if len(self.asset_graph_engine.asset_nodes) > 0 and \
           all(node.value in self.blocked_assets for node in self.asset_graph_engine.asset_nodes.values() if node.in_scope) and \
           not self.pending_mcp_tasks:
            logger.warning("Hard stop: All known assets are blocked and no pending tasks. Dead-end detected.")
            self.objective_met = True
            return True

        return False

    def mark_objective_met(self):
        """Marks the objective as met, typically initiated by LLM's ReportGenerationAction."""
        self.objective_met = True
        logger.info("Objective marked as met by LLM/internal decision.")
        self._save_state()

    def set_final_report(self, report_data: Dict[str, Any]):
        """Sets the final report data."""
        self.final_report_data = report_data
        logger.info("Final report data set in state manager.")
        self._save_state()

    def get_final_report(self) -> Optional[Dict[str, Any]]:
        """Returns the final report data."""
        return self.final_report_data

    def generate_final_report(self) -> Dict[str, Any]:
        """
        Generates the final report using the ReportEngine.
        This method is called by the agent when the objective is met or on hard stop.
        """
        logger.info("Generating final report via ReportEngine...")
        # Create a ReportEngine instance and generate the report
        report_engine = ReportEngine(self, self.tool_metadata_map) # Pass self (StateManager) and tool_metadata
        report_data_model = report_engine.generate_report_data_model()
        final_machine_readable_report = report_engine.generate_machine_readable_report(report_data_model)
        
        # Save human-readable version as well (e.g., Markdown)
        human_readable_report_md = report_engine.generate_human_readable_report(report_data_model, output_format="markdown")
        
        # TODO: Persist these reports to disk within state_dir or a dedicated reports_dir
        # For now, we'll return the machine-readable version.
        
        return final_machine_readable_report
