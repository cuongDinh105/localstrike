"""
schemas/action.py: Defines Pydantic models for LLM raw actions and MCP tool results.
Also defines internal structured actions for agent processing, and the MCP Tool Interface Contract.
"""

import hashlib
import ipaddress
import urllib.parse
from typing import Literal, Dict, Any, Optional, Union, List, Tuple
from pydantic import BaseModel, Field, PrivateAttr, validate_call
from datetime import datetime

# --- LLM's DIRECT RAW OUTPUT SCHEMA ---
class LLMRawActionOutput(BaseModel):
    """
    The strict, flat JSON schema that the LLM MUST return.
    The agent runtime will parse this into more structured internal actions.
    """
    tool_name: str = Field(..., description="The name of the tool to execute or internal agent command (e.g., 'subfinder', 'update_state', 'generate_report').")
    parameters: Dict[str, Any] = Field(..., description="JSON parameters for the tool or internal command. Must be an object, even if empty.")
    reason: str = Field(..., max_length=200, description="A concise justification for selecting this action, within 200 characters.")

# --- AGENT'S INTERNAL STRUCTURED ACTION SCHEMAS ---
# These are used internally by the agent AFTER parsing LLMRawActionOutput
class ToolExecutionAction(BaseModel):
    """
    Represents an internal action to execute a security tool via the HexStrike MCP.
    """
    type: Literal["TOOL_EXECUTION"] = "TOOL_EXECUTION"
    tool_name: str
    parameters: Dict[str, Any]
    reason: str

class StateUpdateAction(BaseModel):
    """
    Represents an internal action to update the agent's assessment state.
    """
    type: Literal["STATE_UPDATE"] = "STATE_UPDATE"
    instruction: str # Maps from reason
    parameters: Dict[str, Any]
    reason: str

class ReportGenerationAction(BaseModel):
    """
    Represents an internal action to trigger the final report generation.
    """
    type: Literal["REPORT_GENERATION"] = "REPORT_GENERATION"
    report_summary: Optional[str] # Maps from reason
    parameters: Dict[str, Any]
    reason: str

class LLMInternalAction(BaseModel):
    """
    The agent's internal representation of an action, including LLM's inferred thought and confidence,
    and also human approval status.
    """
    thought: str = Field(..., description="The LLM's reasoning for this decision (inferred from LLMRawActionOutput reason).")
    action: Union[ToolExecutionAction, StateUpdateAction, ReportGenerationAction] = Field(
        ...,
        discriminator="type",
        description="The specific action the LLM has decided to take, structured for internal processing."
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="The agent's confidence in the LLM's proposed action (defaulted for now).")
    approval_required: bool = Field(False, description="True if this action requires human approval before execution.")
    approval_reason: Optional[str] = Field(None, description="Reason why human approval is required, if any.")


# --- REVIEWER AGENT SCHEMAS ---
class ReviewerFeedback(BaseModel):
    """
    Feedback provided by the Reviewer Agent on a proposed action.
    """
    review_decision: Literal["approve", "caution", "block"] = Field(..., description="The Reviewer Agent's decision.")
    review_reason: str = Field(..., max_length=500, description="Reason for the Reviewer Agent's decision.")
    timestamp: datetime = Field(default_factory=datetime.now, description="Time of the review.")


# --- ASSET GRAPH SCHEMAS ---
class AssetNode(BaseModel):
    """Represents a single asset in the graph."""
    asset_id: str = Field(..., description="Unique ID for the asset (hash of type+value).")
    asset_type: Literal["domain", "subdomain", "ip", "url", "service", "email", "person", "organization", "other"] = Field(..., description="Type of the asset.")
    value: str = Field(..., description="The actual value of the asset (e.g., 'example.com', '192.168.1.1').")
    parent_asset_id: Optional[str] = Field(None, description="ID of the asset from which this asset was discovered/derived.")
    discovery_source_action_id: Optional[str] = Field(None, description="ID of the action that discovered this asset.")
    discovery_timestamp: datetime = Field(default_factory=datetime.now)
    in_scope: bool = Field(False, description="True if this asset is considered in scope.")
    risk_score: float = Field(0.0, description="Calculated risk score for the asset.")

    # Cached for efficiency, machine-only visibility - PrivateAttr won't be serialized by default
    _ip_address: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = PrivateAttr(default=None)
    _domain_parts: Optional[List[str]] = PrivateAttr(default=None)

    def __init__(self, **data: Any):
        super().__init__(**data)
        if self.asset_type == "ip":
            try:
                self._ip_address = ipaddress.ip_address(self.value)
            except ValueError:
                pass # Handled by validation elsewhere, or can set a flag
        elif "domain" in self.asset_type:
            self._domain_parts = self.value.lower().split('.')

    @staticmethod
    def generate_asset_id(asset_type: str, value: str) -> str:
        """Generates a consistent asset_id."""
        return hashlib.sha256(f"{asset_type}:{value}".encode('utf-8')).hexdigest()

class AssetRelationship(BaseModel):
    """Represents a directed relationship between two assets."""
    source_asset_id: str
    target_asset_id: str
    relationship_type: Literal["dns_resolves_to", "subdomain_of", "hosts_service", "linked_to", "owns", "belongs_to", "contains"] = Field(..., description="Type of relationship.")
    timestamp: datetime = Field(default_factory=datetime.now)

class SemanticValidationResult(BaseModel):
    """Result of semantic validation for a proposed target."""
    is_valid: bool = Field(..., description="True if the target is semantically valid and in scope.")
    inferred_asset_type: Optional[str] = Field(None, description="Inferred type of the target (e.g., 'domain', 'ip', 'url').")
    computed_depth: Optional[int] = Field(None, description="Calculated depth of the target from the initial scope roots.")
    semantic_violation_reason: Optional[str] = Field(None, description="Detailed reason for semantic violation, if any.")
    resolved_ip: Optional[str] = Field(None, description="Resolved IP address if target was a domain and resolution happened.")
    resolved_asset_id: Optional[str] = Field(None, description="Asset ID of the target after resolution/inference.")


# --- EXECUTED ACTION LOG SCHEMA ---
class ExecutedAction(BaseModel):
    """
    A comprehensive log entry for an action proposed by the LLM and its lifecycle.
    Stored in StateManager.executed_actions_log.
    """
    action_id: str = Field(..., description="Unique identifier for this specific action instance.")
    llm_internal_action: LLMInternalAction = Field(..., description="The internal action object proposed by the LLM.")
    status: Literal[
        "PROPOSED", 
        "WAITING_FOR_REVIEW", 
        "REVIEW_APPROVED", 
        "REVIEW_CAUTION", 
        "REVIEW_BLOCKED", 
        "WAITING_FOR_APPROVAL", 
        "APPROVED_BY_HUMAN", 
        "REJECTED_BY_HUMAN", 
        "MODIFIED_APPROVED", 
        "ABORTED_BY_HUMAN", 
        "EXECUTING", 
        "COMPLETED", 
        "FAILED",
        "SCOPE_BLOCKED" # New status for scope violations
    ] = Field(..., description="Current status in the action lifecycle.")
    error_message: Optional[str] = Field(None, description="Error message if the action failed or was rejected.")
    start_time: datetime = Field(..., description="Timestamp when the action was proposed/started.")
    end_time: Optional[datetime] = Field(None, description="Timestamp when the action completed or was terminated.")
    mcp_task_id: Optional[str] = Field(None, description="MCP task ID if it was a tool execution.")
    
    reviewer_feedback: Optional[ReviewerFeedback] = Field(None, description="Feedback from the Reviewer Agent.")
    
    human_decision_time: Optional[datetime] = Field(None, description="Timestamp of human's decision.")
    human_decision_id: Optional[str] = Field(None, description="Unique ID for the human interaction event.")
    modified_parameters: Optional[Dict[str, Any]] = Field(None, description="Parameters modified by human, if any.")

    scope_validation_result: Optional[SemanticValidationResult] = Field(None, description="Result of semantic scope validation.") # Store scope validation result


# --- MCP TOOL INTERFACE CONTRACT SCHEMAS ---

class ToolError(BaseModel):
    """Unified error model for MCP tools."""
    code: str = Field(..., description="Standardized error code (e.g., TOOL_TIMEOUT, INVALID_PARAMS, PERMISSION_DENIED).")
    message: str = Field(..., description="Human-readable error message.")
    is_retryable: bool = Field(..., description="True if the error is temporary and the tool can be retried.")
    details: Optional[Dict[str, Any]] = Field(None, description="Optional technical details for machine-only visibility.")

class ParameterContract(BaseModel):
    """JSON Schema definition for tool parameters."""
    type: str = Field("object", const=True) # Must be 'object' for parameters
    properties: Dict[str, Any] = Field(..., description="Mapping of parameter names to their JSON Schema definitions.")
    required: Optional[List[str]] = Field(None, description="List of required parameter names.")
    # Add other JSON Schema keywords as needed, e.g., 'description', 'examples'

class ToolMetadata(BaseModel):
    """Standard metadata schema that every MCP tool must expose."""
    name: str = Field(..., description="Canonical, immutable tool name.")
    description: str = Field(..., description="LLM-facing, sanitized description of the tool's purpose.")
    category: Literal["recon", "scanning", "exploitation_support", "post_exploitation_support", "analysis", "reporting", "utility", "internal"] = Field(..., description="Main functional category of the tool.")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(..., description="Assessment of potential impact to target.")
    idempotency: bool = Field(..., description="True if running the tool multiple times with same params produces no different side effects.")
    expected_exec_time: Literal["instant", "short", "medium", "long", "extended"] = Field(..., description="Typical execution time class.")
    output_sensitivity: Literal["none", "low", "medium", "high"] = Field(..., description="Indicates if tool output may contain sensitive information.")
    preconditions: Dict[str, Any] = Field(default_factory=dict, description="State requirements for tool execution (machine-only).")
    postconditions: Dict[str, Any] = Field(default_factory=dict, description="Expected state impact after successful tool execution (machine-only).")
    parameters_schema: ParameterContract = Field(..., description="JSON Schema for the tool's input parameters.")

class ToolOutput(BaseModel):
    """Standardized output format returned by ALL tools from MCP."""
    summary: str = Field(..., description="Concise, LLM-facing summary of the tool's execution result.")
    assets_found: List[str] = Field(default_factory=list, description="New assets discovered (e.g., subdomains, IPs).")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Structured findings identified by the tool (severity, description, etc.).")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="Performance or result metrics from tool execution.")
    suggested_next_steps: List[str] = Field(default_factory=list, description="Machine-readable suggestions for agent's next actions.")
    raw_output_ref: str = Field(..., description="Hash reference to the stored raw tool output (machine-only visibility).")
    warnings: List[str] = Field(default_factory=list, description="Non-critical warnings from tool execution.")

class ToolResult(BaseModel):
    """
    Represents the result structure returned by HexStrike MCP for a completed or pending task.
    Updated to use ToolOutput and ToolError models.
    """
    task_id: str = Field(..., description="Unique identifier for the executed task.")
    tool_name: str = Field(..., description="Name of the tool that was executed.")
    status: Literal["PENDING", "COMPLETED", "FAILED", "WARNINGS"] = Field(..., description="Current status of the task.")
    timestamp: datetime = Field(default_factory=datetime.now, description="Time MCP responded.")
    output: Optional[ToolOutput] = Field(None, description="Standardized, processed output from the tool execution, if completed.")
    error: Optional[ToolError] = Field(None, description="Unified error details if the tool execution failed.")