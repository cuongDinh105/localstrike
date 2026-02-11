"""
agent/agent.py: Orchestrates the LocalStrike AI agent's assessment loop.
"""

import logging
import time
import json
import hashlib # For human_decision_id
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from jsonschema import validate, ValidationError as JSONSchemaValidationError # For validating LLM parameters against tool schema

from llm.client import LLMClient
from mcp.client import MCPClient
from schemas.action import LLMRawActionOutput, LLMInternalAction, ToolExecutionAction, StateUpdateAction, ReportGenerationAction, ToolMetadata, ParameterContract, ReviewerFeedback, SemanticValidationResult # Import ReviewerFeedback, SemanticValidationResult
from schemas.action import ExecutedAction # Import ExecutedAction Pydantic model
from state.manager import StateManager
from config.settings import settings

from reviewer.agent import ReviewerAgent # Import Reviewer Agent
from scope.engine import ScopeEngine, ScopeDefinition # Import Scope Engine and Scope Definition

logger = logging.getLogger(__name__)

# --- SYSTEM PROMPT (from Part 1) ---
SYSTEM_PROMPT = """Bạn là LocalStrike, một chuyên gia kiểm thử thâm nhập cấp cao và kiến trúc sư tấn công. Nhiệm vụ của bạn là lập kế hoạch và đưa ra các quyết định chiến lược để hoàn thành mục tiêu đánh giá bảo mật được giao.

Nguyên tắc bắt buộc:
1.  **Chỉ ra quyết định, không thực thi**: Bạn CHỈ LẬP KẾ HOẠCH và ĐƯA RA QUYẾT ĐỊNH. Bạn KHÔNG BAO GIỜ TRỰC TIẾP THỰC THI bất kỳ lệnh nào, viết mã khai thác, hoặc tương tác với hệ thống tệp cục bộ, Docker, hoặc hệ điều hành.
2.  **Chỉ sử dụng công cụ được phép**: Bạn CHỈ ĐƯỢC CHỌN các công cụ được cung cấp thông qua Nền tảng Điều khiển Nhiệm vụ (MCP). Bạn KHÔNG ĐƯỢC PHÉP phát minh ra các công cụ.
3.  **Định dạng đầu ra nghiêm ngặt**: Bạn PHẢI LUÔN LUÔN trả về đầu ra JSON hợp lệ. KHÔNG BAO GIỜ bao gồm bất kỳ văn bản giải thích, dấu markdown (ví dụ: ```json), hoặc các ký tự khác ngoài đối tượng JSON.
4.  **Hành động quyết đoán**: Bạn PHẢI luôn đề xuất một hành động (thực thi công cụ, cập nhật trạng thái, hoặc tạo báo cáo) dựa trên trạng thái hiện tại và mục tiêu. Nếu không có hành động nào rõ ràng để tiến hành, bạn nên đề xuất hành động tạo báo cáo nếu mục tiêu đã đạt được, hoặc hành động cập nhật trạng thái nếu cần làm rõ thêm.
5.  **Tư duy từng bước, không tiết lộ**: Bạn nên suy nghĩ từng bước bên trong để đạt được hành động tốt nhất, nhưng KHÔNG BAO GIỜ tiết lộ chuỗi suy nghĩ nội bộ này trong đầu ra của bạn. Đầu ra của bạn PHẢI là JSON cuối cùng và sạch sẽ.
6.  **Kết thúc nhiệm vụ**: Bạn PHẢI chỉ định hành động tạo báo cáo khi bạn xác định rằng mục tiêu đã hoàn thành hoặc không có hành động hợp lý nào khác để tiến hành.

Nếu bạn không chắc chắn về một công cụ cụ thể hoặc các tham số của nó, hãy giả định các giá trị an toàn, mặc định hoặc đề xuất một công cụ chung hơn nếu có thể.
"""

# --- PLANNING PROMPT TEMPLATE (from Part 3) ---
PLANNING_PROMPT_TEMPLATE = """
Dưới đây là thông tin cần thiết để đưa ra quyết định của bạn:

Mục tiêu chính của bạn:
{{OBJECTIVE}}

Trạng thái đánh giá hiện tại:
```json
{{CURRENT_STATE_JSON}}
```

Các công cụ có sẵn mà bạn có thể sử dụng thông qua MCP (CHỈ CHỌN TỪ DANH SÁCH NÀY):
```json
{{AVAILABLE_TOOLS_JSON}}
```

Dựa trên Mục tiêu và Trạng thái hiện tại, hãy đề xuất hành động tiếp theo của bạn dưới dạng đối tượng JSON HỢP LỆ, tuân thủ schema nghiêm ngặt sau.
NHẮC LẠI: CHỈ ĐẦU RA JSON, KHÔNG VĂN BẢN KHÁC, KHÔNG DẤU MARKDOWN.

Schema JSON bắt buộc:
```json
{{ACTION_JSON_SCHEMA}}
```
"""

# --- AGENT INTERNAL COMMANDS ---
# Define internal commands as ToolMetadata for consistency
INTERNAL_COMMAND_METADATA = {
    "update_state": ToolMetadata(
        name="update_state",
        description="Updates the agent's internal state with new information or changes current focus. Parameters detail the update.",
        category="internal", risk_level="low", idempotency=True, expected_exec_time="instant", output_sensitivity="none",
        preconditions={}, postconditions={},
        parameters_schema=ParameterContract(type="object", properties={"instruction": {"type": "string"}, "details": {"type": "object"}}, required=["instruction"])
    ),
    "generate_report": ToolMetadata(
        name="generate_report",
        description="Signals that the assessment objective is met and a final report should be generated.",
        category="internal", risk_level="low", idempotency=True, expected_exec_time="instant", output_sensitivity="none",
        preconditions={}, postconditions={},
        parameters_schema=ParameterContract(type="object", properties={"report_summary": {"type": "string"}}, required=["report_summary"])
    )
}


class LocalStrikeAgent:
    """
    The core orchestration engine for the LocalStrike AI agent.
    Manages the assessment lifecycle: LLM prompting, action execution, and state updates.
    """
    def __init__(self, objective: str, target: str):
        self.objective = objective
        self.initial_target = target
        self.llm_client = LLMClient()
        self.mcp_client = MCPClient()
        self.state_manager = StateManager() # StateManager loads/initializes itself
        
        # Initialize ScopeDefinition (could come from config/user input)
        self.scope_definition = ScopeDefinition(
            initial_target_value=target,
            allowed_domains=[target] if '.' in target and not target.replace('.','').isdigit() else [],
            allowed_ip_ranges=[target + "/32"] if '.' not in target or target.replace('.','').isdigit() else [], # Simple IP check
            max_depth=settings.DEFAULT_SCOPE_MAX_DEPTH
        )
        # Pass scope_definition to state manager
        self.state_manager.initialize(objective, target, scope_definition=self.scope_definition) # Overwrite or confirm initial objective/target
        
        # Tools allowed for the LLM to choose, including MCP tools and internal commands
        self.tool_metadata_map: Dict[str, ToolMetadata] = {} # Store fetched tool metadata
        self.allowed_tools: Dict[str, ToolMetadata] = self._get_allowed_tools() # Populate allowed_tools and tool_metadata_map
        # Pass the tool_metadata_map to the state_manager for report generation
        self.state_manager.tool_metadata_map = self.tool_metadata_map

        # Initialize Reviewer Agent
        self.reviewer_agent = ReviewerAgent()
        
        # Initialize Scope Engine
        # ScopeEngine needs the AssetGraphEngine from StateManager, which is initialized in state_manager.initialize
        self.scope_engine = ScopeEngine(self.scope_definition, self.state_manager.asset_graph_engine)

        logger.info(f"LocalStrike Agent initialized with objective: '{objective}' and target: '{target}'")

    def _get_allowed_tools(self) -> Dict[str, ToolMetadata]:
        """
        Retrieves the list of tools the LLM is allowed to use.
        Fetches metadata from MCP and combines with agent internal commands.
        """
        # Fetch MCP tools metadata
        mcp_tool_list: List[ToolMetadata] = []
        try:
            mcp_tool_list = self.mcp_client.list_tools()
        except Exception as e:
            logger.error(f"Failed to list tools from MCP: {e}. Only internal commands will be available.")

        # Filter MCP tools if necessary (e.g., by risk_level)
        # For now, include all MCP tools
        
        # Convert to a map for easy lookup
        tools_map = {tool.name: tool for tool in mcp_tool_list}

        # Add AGENT_INTERNAL_COMMANDS as ToolMetadata objects
        tools_map.update(INTERNAL_COMMAND_METADATA) # Directly use the defined metadata
        
        self.tool_metadata_map = tools_map
        return tools_map

    def _determine_approval_level(self, 
                                  internal_action: LLMInternalAction, 
                                  reviewer_feedback: Optional[ReviewerFeedback] = None
                                  ) -> Tuple[bool, Optional[str]]:
        """
        Deterministically determines if an action requires human approval.
        (Part 1: Approval Levels)
        """
        action = internal_action.action
        tool_name = action.tool_name if isinstance(action, ToolExecutionAction) else action.type # Use type for internal commands
        tool_meta = self.tool_metadata_map.get(tool_name) # Retrieve full metadata

        if not tool_meta:
            # This should ideally not happen due to _process_llm_raw_output validation
            return True, f"Unknown tool/command '{tool_name}' proposed by LLM."
        
        # Rule 0: Reviewer Agent's blocking decision is paramount
        if reviewer_feedback and reviewer_feedback.review_decision == "block":
            return True, f"Reviewer Agent explicitly BLOCKED this action: {reviewer_feedback.review_reason}"

        # Rule 1: High/Critical risk level
        if tool_meta.risk_level in ["high", "critical"]:
            return True, f"Action '{tool_name}' has a '{tool_meta.risk_level}' risk level, requiring human approval."

        # Rule 2: High output sensitivity
        if tool_meta.output_sensitivity == "high":
            return True, f"Action '{tool_name}' output is marked as 'high' sensitivity, requiring human approval."

        # Rule 3: Execution on a blocked asset (use asset_graph_engine's knowledge)
        if isinstance(action, ToolExecutionAction):
            target_value = action.parameters.get("target")
            if target_value:
                target_type = self.state_manager.asset_graph_engine._infer_asset_type(target_value)
                target_id = self.state_manager.asset_graph_engine.AssetNode.generate_asset_id(target_type, target_value)
                if target_id in self.state_manager.blocked_assets: # Check against blocked asset IDs
                     return True, f"LLM proposed action '{tool_name}' on a blocked asset '{target_value}'."
        
        # Rule 4: Action type considerations
        if action.type == "TOOL_EXECUTION":
            # Example: Any non-reconnaissance tool execution requires approval if risk is not low.
            if tool_meta.category != "recon" and tool_meta.risk_level != "low":
                return True, f"Non-reconnaissance tool '{tool_name}' with risk '{tool_meta.risk_level}' requires approval."
            
            # Example: Exploitation support tools always require approval
            if tool_meta.category == "exploitation_support":
                 return True, f"Exploitation support tool '{tool_name}' always requires approval."

        # Rule 5: Critical state warnings (e.g., agent is lost)
        if self.state_manager.no_progress_count >= settings.NO_PROGRESS_THRESHOLD_FOR_APPROVAL: # New setting
            return True, f"No significant progress for {self.state_manager.no_progress_count} iterations. Review required."

        # Default: Auto-approve
        return False, None


    def _get_human_input(self, internal_action: LLMInternalAction, action_id: str, reviewer_feedback: Optional[ReviewerFeedback], scope_validation_result: SemanticValidationResult) -> Dict[str, Any]:
        """
        Handles CLI interaction for human approval.
        (Part 4: Human Decision Interface)
        """
        logger.warning(f"\n--- HUMAN INTERVENTION REQUIRED --- (Action ID: {action_id})")
        logger.warning(f"Reason for Approval: {internal_action.approval_reason}")
        logger.warning(f"LLM Thought: {internal_action.thought}")
        logger.warning(f"Proposed Action Type: {internal_action.action.type}")
        
        action_details = internal_action.action
        if isinstance(action_details, ToolExecutionAction):
            tool_meta = self.tool_metadata_map.get(action_details.tool_name)
            logger.warning(f"  Tool Name: {action_details.tool_name}")
            logger.warning(f"  Tool Description: {tool_meta.description if tool_meta else 'N/A'}")
            logger.warning(f"  Tool Category: {tool_meta.category if tool_meta else 'N/A'}")
            logger.warning(f"  Risk Level: {tool_meta.risk_level if tool_meta else 'N/A'}")
            logger.warning(f"  Parameters: {json.dumps(action_details.parameters, indent=2)}")
        elif isinstance(action_details, StateUpdateAction):
            logger.warning(f"  Instruction: {action_details.instruction}")
            logger.warning(f"  Parameters: {json.dumps(action_details.parameters, indent=2)}")
        elif isinstance(action_details, ReportGenerationAction):
            logger.warning(f"  Summary: {action_details.report_summary}")

        if reviewer_feedback:
            logger.warning(f"\n--- REVIEWER AGENT FEEDBACK ---")
            logger.warning(f"  Decision: {reviewer_feedback.review_decision.upper()}")
            logger.warning(f"  Reason: {reviewer_feedback.review_reason}")
        
        # Critical: If scope validation failed but we reached here due to some logic error, alert human
        if not scope_validation_result.is_allowed: # This should ideally be caught before HITL
            logger.critical(f"\n!!! CRITICAL ERROR: SCOPE VIOLATION SHOULD HAVE BLOCKED THIS ACTION !!!")
            logger.critical(f"  Violation Type: {scope_validation_result.violation_type}")
            logger.critical(f"  Reason: {scope_validation_result.violation_reason}")
            logger.critical("  HUMAN APPROVAL CANNOT OVERRIDE SCOPE BLOCKS. ABORTING.")
            return {"decision": "abort"}


        print("\nPlease choose an action:")
        print("  [a] - Approve: Execute the action as proposed.")
        print("  [r] - Reject: Reject the action. LLM will try again.")
        print("  [m] - Modify: Modify parameters and then approve.")
        print("  [x] - Abort: Terminate the entire assessment.")

        while True:
            choice = input("Your choice (a/r/m/x): ").lower().strip()
            if choice == 'a':
                return {"decision": "approved", "modified_action": internal_action}
            elif choice == 'r':
                return {"decision": "rejected"}
            elif choice == 'm':
                print("\n--- MODIFYING ACTION PARAMETERS ---")
                print("Current parameters:")
                print(json.dumps(action_details.parameters, indent=2))
                new_params_str = input("Enter new JSON parameters (or leave empty to keep current): ")
                try:
                    new_parameters = json.loads(new_params_str) if new_params_str else action_details.parameters
                    
                    # Create a new action with modified parameters
                    modified_action_details = action_details.model_copy(update={"parameters": new_parameters})
                    modified_internal_action = internal_action.model_copy(update={"action": modified_action_details})

                    # Re-validate modified parameters against tool schema
                    if isinstance(modified_action_details, ToolExecutionAction):
                        tool_meta = self.tool_metadata_map[modified_action_details.tool_name]
                        validate(instance=new_parameters, schema=tool_meta.parameters_schema.model_dump())
                    
                    return {"decision": "modified", "modified_action": modified_internal_action}
                except (json.JSONDecodeError, JSONSchemaValidationError) as e:
                    print(f"Invalid JSON or parameters for tool: {e}. Please try again.")
                except Exception as e:
                    print(f"Error modifying parameters: {e}. Please try again.")
            elif choice == 'x':
                return {"decision": "abort"}
            else:
                print("Invalid choice. Please enter 'a', 'r', 'm', or 'x'.")

    def run(self) -> Optional[Dict[str, Any]]:
        """
        Runs the main agent loop until the objective is met or an error occurs.
        """
        if not self.mcp_client.check_health():
            logger.error("HexStrike MCP is not healthy. Cannot start agent execution.")
            return None

        while not self.state_manager.is_objective_met():
            try:
                # 1. Observe & Orient: Get LLM's next action
                prompts = self._generate_llm_prompt()
                
                # Get raw output from LLM and validate
                raw_llm_output: LLMRawActionOutput = self.llm_client.get_action(prompts["system_prompt"], prompts["user_prompt"])
                
                # Process raw output into internal structured action
                internal_action = self._process_llm_raw_output(raw_llm_output)
                
                # --- Scope Enforcement Engine Check ---
                # Scope check is the first line of defense, overriding everything else
                scope_result = self.scope_engine.validate_action(internal_action, self.state_manager.get_llm_visible_state())
                if not scope_result.is_allowed:
                    logger.critical(f"Action BLOCKED by Scope Engine: {scope_result.violation_reason}")
                    # Log this action as SCOPE_BLOCKED
                    action_id = self.state_manager.add_executed_action(
                        llm_internal_action=internal_action, 
                        status="SCOPE_BLOCKED", 
                        error=scope_result.violation_reason,
                        scope_validation_result=scope_result # Store the full result for audit
                    )
                    time.sleep(settings.AGENT_LOOP_DELAY_SECONDS) # Allow time for observation
                    continue # Skip execution and go to next LLM planning loop


                # --- Multi-Agent: Reviewer Agent Feedback ---
                # Reviewer Agent is non-executing and provides feedback BEFORE human approval
                reviewer_feedback: ReviewerFeedback = self.reviewer_agent.review_action(
                    internal_action, 
                    self.state_manager.get_llm_visible_state(), 
                    self.allowed_tools
                )
                logger.info(f"Reviewer Agent Feedback: Decision='{reviewer_feedback.review_decision}', Reason='{reviewer_feedback.review_reason}'")

                # Re-determine if human approval is required, now considering reviewer feedback
                approval_required, approval_reason = self._determine_approval_level(internal_action, reviewer_feedback)
                internal_action.approval_required = approval_required
                internal_action.approval_reason = approval_reason

                logger.info(f"Agent Action (parsed from LLM): {internal_action.action.type}. Reason: {internal_action.action.reason} (Confidence: {internal_action.confidence:.2f}). Approval Required: {internal_action.approval_required}")

                # Log the proposed action (before execution) including reviewer feedback and initial scope validation
                action_id = self.state_manager.add_executed_action(
                    llm_internal_action=internal_action, 
                    status="PROPOSED", 
                    reviewer_feedback=reviewer_feedback,
                    scope_validation_result=scope_result # Store scope validation result for audit
                )

                # --- Safeguard: Reviewer Agent Block ---
                if reviewer_feedback.review_decision == "block":
                    self.state_manager.update_executed_action_status(action_id, "REVIEW_BLOCKED", error=reviewer_feedback.review_reason)
                    logger.warning(f"Reviewer Agent BLOCKED action ID: {action_id}. Reason: {reviewer_feedback.review_reason}. LLM will re-plan.")
                    time.sleep(settings.AGENT_LOOP_DELAY_SECONDS) # Allow time for observation
                    continue # Skip execution and go to next LLM planning loop

                # --- HITL Approval Gate ---
                final_action_to_execute: LLMInternalAction = internal_action
                if internal_action.approval_required:
                    # Update status based on reviewer feedback if not blocked
                    if reviewer_feedback.review_decision == "approve":
                        self.state_manager.update_executed_action_status(action_id, "REVIEW_APPROVED")
                    elif reviewer_feedback.review_decision == "caution":
                        self.state_manager.update_executed_action_status(action_id, "REVIEW_CAUTION")

                    self.state_manager.update_executed_action_status(action_id, "WAITING_FOR_APPROVAL")
                    human_decision = self._get_human_input(internal_action, action_id, reviewer_feedback, scope_result) # Pass scope_result to human input for context
                    
                    # Generate a unique human decision ID
                    human_decision_id = hashlib.sha256(f"{action_id}-{datetime.now().isoformat()}-{human_decision['decision']}".encode()).hexdigest()

                    if human_decision["decision"] == "approved":
                        self.state_manager.update_executed_action_status(
                            action_id, "APPROVED_BY_HUMAN", 
                            human_decision_time=datetime.now(), 
                            human_decision_id=human_decision_id
                        )
                        # final_action_to_execute remains internal_action
                    elif human_decision["decision"] == "modified":
                        modified_internal_action = human_decision["modified_action"]
                        # Log the original action as REJECTED_BY_HUMAN
                        self.state_manager.update_executed_action_status(
                            action_id, "REJECTED_BY_HUMAN_MODIFIED_SUBSEQUENTLY", 
                            human_decision_time=datetime.now(), 
                            human_decision_id=human_decision_id,
                            modified_parameters=modified_internal_action.action.parameters # Store modified params for audit
                        )
                        # Add the modified action as a new PROPOSED action, initiated by human
                        # For audit, this is a distinct action in the log
                        action_id = self.state_manager.add_executed_action(
                            llm_internal_action=modified_internal_action, 
                            status="APPROVED_BY_HUMAN", # Human approved modified version
                            reviewer_feedback=reviewer_feedback, # Keep same reviewer feedback for context
                            scope_validation_result=scope_result # Keep same scope validation result for context
                        )
                        final_action_to_execute = modified_internal_action
                        logger.info(f"Action modified and approved by human. New Action ID: {action_id}")
                    elif human_decision["decision"] == "rejected":
                        self.state_manager.update_executed_action_status(
                            action_id, "REJECTED_BY_HUMAN", 
                            human_decision_time=datetime.now(), 
                            human_decision_id=human_decision_id
                        )
                        logger.warning(f"Human rejected action ID: {action_id}. LLM will plan next step.")
                        # This iteration effectively ends here, LLM will get updated state without this action executed
                        time.sleep(settings.AGENT_LOOP_DELAY_SECONDS) # Give human time to read output
                        continue # Skip execution and go to next LLM planning loop
                    elif human_decision["decision"] == "abort":
                        self.state_manager.update_executed_action_status(
                            action_id, "ABORTED_BY_HUMAN", 
                            human_decision_time=datetime.now(), 
                            human_decision_id=human_decision_id
                        )
                        self.state_manager.force_terminate = True
                        logger.critical("Assessment aborted by human.")
                        break # Exit agent loop
                
                # 2. Act: Execute the action based on LLM's (or human's modified) decision
                action_type = final_action_to_execute.action.type
                if action_type == "TOOL_EXECUTION":
                    tool_action: ToolExecutionAction = final_action_to_execute.action # Type hint for clarity
                    logger.info(f"Executing tool: {tool_action.tool_name} with params: {tool_action.parameters}")
                    try:
                        # Agent performs pre-call validation using tool_meta.parameters_schema
                        tool_meta = self.tool_metadata_map[tool_action.tool_name]
                        validate(instance=tool_action.parameters, schema=tool_meta.parameters_schema.model_dump())
                        
                        task_id = self.mcp_client.execute_tool(tool_action.tool_name, tool_action.parameters)
                        self.state_manager.add_pending_mcp_task(task_id, final_action_to_execute, action_id) # Store internal action and its action_id
                        self.state_manager.update_executed_action_status(action_id, "EXECUTING", mcp_task_id=task_id)
                    except JSONSchemaValidationError as e:
                        logger.error(f"Pre-execution parameter validation failed for tool '{tool_action.tool_name}': {e.message}")
                        self.state_manager.update_executed_action_status(action_id, "FAILED", error=f"Parameter validation failed: {e.message}")
                    except Exception as e:
                        logger.error(f"Failed to execute tool {tool_action.tool_name} via MCP: {e}.")
                        self.state_manager.update_executed_action_status(action_id, "FAILED", error=str(e))

                elif action_type == "STATE_UPDATE":
                    state_update_action: StateUpdateAction = final_action_to_execute.action # Type hint for clarity
                    logger.info(f"Updating internal state: {state_update_action.instruction}. Details: {state_update_action.parameters}")
                    self.state_manager.update_internal_state(state_update_action.instruction, state_update_action.parameters)
                    self.state_manager.update_executed_action_status(action_id, "COMPLETED")

                elif action_type == "REPORT_GENERATION":
                    report_gen_action: ReportGenerationAction = final_action_to_execute.action # Type hint for clarity
                    logger.info(f"LLM requested report generation. Marking objective met. Summary: {report_gen_action.report_summary}")
                    final_report_data = self.state_manager.generate_final_report()
                    self.state_manager.set_final_report(final_report_data)
                    self.state_manager.mark_objective_met()
                    self.state_manager.update_executed_action_status(action_id, "COMPLETED")
                else:
                    logger.warning(f"Unknown internal action type received: {action_type}. Skipping.")
                    self.state_manager.update_executed_action_status(action_id, "FAILED", error="Unknown action type")

                # 3. Review: Check for completed tasks and update state
                self._process_completed_tasks()

                if not self.state_manager.is_objective_met():
                    time.sleep(settings.AGENT_LOOP_DELAY_SECONDS)

            except ValueError as e:
                logger.error(f"Validation or processing error with LLM output: {e}.")
                # Log this failure in the executed actions log as well
                dummy_action = LLMInternalAction(
                    thought=f"LLM output validation or processing failed: {e}",
                    action=StateUpdateAction(type="STATE_UPDATE", instruction=f"Handle LLM validation error: {e}", parameters={}, reason=f"Validation error: {e}"),
                    confidence=0.0
                )
                action_id_for_error = self.state_manager.add_executed_action(llm_internal_action=dummy_action, status="FAILED", error=str(e)) # Log this new action
                time.sleep(settings.AGENT_LOOP_DELAY_SECONDS * 2)
            except Exception as e:
                logger.critical(f"An unhandled error occurred in agent loop: {e}", exc_info=True)
                # Log this critical failure
                dummy_action = LLMInternalAction(
                    thought=f"Critical agent error: {e}",
                    action=StateUpdateAction(type="STATE_UPDATE", instruction=f"Handle critical agent error: {e}", parameters={}, reason=f"Critical error: {e}"),
                    confidence=0.0
                )
                self.state_manager.add_executed_action(llm_internal_action=dummy_action, status="FAILED", error=str(e))
                self.state_manager.force_terminate = True # Signal for hard stop
                if settings.DEBUG_MODE:
                    raise
                time.sleep(settings.AGENT_LOOP_DELAY_SECONDS * 2)

        logger.info("Agent objective met or loop terminated.")
        return self.state_manager.get_final_report()

    def _process_completed_tasks(self):
        """
        Checks MCP for completed tasks and updates the state manager.
        """
        # Get pending_mcp_tasks from state_manager (it now stores Tuple[LLMInternalAction, str])
        pending_tasks = list(self.state_manager.pending_mcp_tasks.items()) 
        if not pending_tasks:
            return

        for task_id, (llm_internal_action, action_id) in pending_tasks: # Unpack the tuple
            try:
                result = self.mcp_client.get_task_result(task_id)
                if result and result.status != "PENDING":
                    self.state_manager.process_tool_result(result) # This will update the executed_actions_log status
            except Exception as e:
                logger.warning(f"Could not retrieve status for task {task_id} from MCP: {e}")
                # Log this failure in the executed actions log
                self.state_manager.update_executed_action_status(
                    action_id=action_id,
                    status="FAILED",
                    error=str(e),
                    mcp_task_id=task_id
                )
                # Mark tool's original action as failed after repeated attempts
                # TODO: Implement retry logic for get_task_result in MCPClient
