from typing import Literal, Dict, Any, Optional, Union
from pydantic import BaseModel, Field

class ToolExecutionAction(BaseModel):
    """
    Represents an action to execute a security tool via the HexStrike MCP.
    """
    type: Literal["TOOL_EXECUTION"] = "TOOL_EXECUTION"
    tool_name: str = Field(..., description="The name of the tool to be executed by MCP (e.g., 'subfinder').")
    parameters: Dict[str, Any] = Field(..., description="JSON parameters for the tool. These should match the MCP tool's expected input schema.")

class StateUpdateAction(BaseModel):
    """
    Represents an action to update the agent's internal assessment state.
    """
    type: Literal["STATE_UPDATE"] = "STATE_UPDATE"
    instruction: str = Field(..., description="A specific instruction for the agent to update its internal state (e.g., 'Add discovered subdomains to the target list').")

class ReportGenerationAction(BaseModel):
    """
    Represents an action to trigger the final report generation.
    """
    type: Literal["REPORT_GENERATION"] = "REPORT_GENERATION"
    report_summary: Optional[str] = Field(None, description="A brief summary or context for the report to be generated.")

class LLMAction(BaseModel):
    """
    The top-level schema for the JSON action that the LLM must return.
    It includes the LLM's thought process and the chosen action.
    """
    thought: str = Field(..., description="The LLM's reasoning for this decision based on the current state and objective.")
    action: Union[ToolExecutionAction, StateUpdateAction, ReportGenerationAction] = Field(
        ...,
        discriminator="type",
        description="The specific action the LLM has decided to take."
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="The LLM's confidence level in the proposed action (0.0-1.0).")

# Pydantic model for tool results (simplified for now, will be expanded)
class ToolResult(BaseModel):
    task_id: str
    tool_name: str
    status: Literal["PENDING", "COMPLETED", "FAILED"]
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
