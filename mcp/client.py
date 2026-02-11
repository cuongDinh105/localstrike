"""
mcp/client.py: Handles REST API communication with the HexStrike Mission Control Platform (MCP).
"""

import requests
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime # Import datetime for ToolResult timestamp

from config.settings import settings
from schemas.action import ToolResult, ToolMetadata, ToolError, ToolOutput # Import new models
from pydantic import ValidationError # For validating ToolMetadata, ToolResult

logger = logging.getLogger(__name__)

class MCPClient:
    """
    Client for interacting with the HexStrike Mission Control Platform (MCP) API.
    All tool execution requests and task status checks go through this client.
    """
    def __init__(self):
        self.base_url = settings.MCP_BASE_URL
        if not self.base_url:
            raise ValueError("MCP_BASE_URL must be configured.")
        logger.info(f"MCPClient initialized for base URL: '{self.base_url}'")

    def _make_request(self, method: str, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Helper method to make HTTP requests to the MCP API.
        """
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        
        try:
            response = requests.request(method, url, headers=headers, json=json_data, timeout=settings.MCP_TIMEOUT_SECONDS)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.Timeout:
            logger.error(f"MCP API call to {url} timed out after {settings.MCP_TIMEOUT_SECONDS} seconds.")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with MCP API at {url}: {e}")
            raise

    def check_health(self) -> bool:
        """
        Checks the health endpoint of the MCP.
        """
        path = "/health"
        try:
            response = self._make_request("GET", path)
            status = response.get("status") == "healthy"
            if not status:
                logger.warning(f"MCP /health endpoint returned: {response}")
            return status
        except Exception as e:
            logger.error(f"MCP Health check failed: {e}")
            return False

    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        Sends a request to MCP to execute a specific security tool.
        Returns the task_id if the execution request was successful.
        """
        path = f"/api/tools/{tool_name}"
        logger.info(f"Requesting MCP to execute tool '{tool_name}' with parameters: {parameters}")
        try:
            response = self._make_request("POST", path, json_data=parameters)
            # MCP is expected to return a dictionary with a 'task_id'
            task_id = response.get("task_id")
            if task_id:
                logger.info(f"Tool '{tool_name}' execution requested. Task ID: {task_id}")
                return task_id
            else:
                raise ValueError(f"MCP did not return a 'task_id' for tool '{tool_name}'. Response: {response}")
        except Exception as e:
            logger.error(f"Failed to execute tool '{tool_name}': {e}")
            raise

    def get_task_result(self, task_id: str) -> Optional[ToolResult]:
        """
        Retrieves the result of an asynchronously executed task from MCP.
        Returns ToolResult object or None if task is still pending or not found.
        """
        path = f"/api/process/get-task-result/{task_id}"
        try:
            response_data = self._make_request("GET", path)
            
            # If MCP explicitly returns PENDING status in the top-level
            # Need to provide default values for other ToolResult fields.
            if response_data.get("status") == "PENDING":
                return ToolResult(
                    task_id=task_id, 
                    tool_name=response_data.get("tool_name", "unknown"), 
                    status="PENDING",
                    timestamp=datetime.fromisoformat(response_data.get("timestamp", datetime.now().isoformat()))
                )
            
            # Otherwise, validate the full response against ToolResult schema
            return ToolResult.model_validate(response_data)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Task ID {task_id} not found on MCP.")
                return None
            raise # Re-raise other HTTP errors
        except ValidationError as e:
            logger.error(f"MCP response for task '{task_id}' did not match ToolResult schema: {e}. Data: {response_data}")
            raise ValueError(f"MCP response invalid: {e}")
        except Exception as e:
            logger.error(f"Failed to get result for task '{task_id}': {e}")
            raise
    
    def get_tool_metadata(self, tool_name: str) -> Optional[ToolMetadata]:
        """
        Retrieves the metadata for a specific tool from MCP.
        """
        path = f"/api/tools/metadata/{tool_name}"
        try:
            response_data = self._make_request("GET", path)
            return ToolMetadata.model_validate(response_data)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Tool metadata for '{tool_name}' not found on MCP.")
                return None
            raise
        except ValidationError as e:
            logger.error(f"MCP response for tool metadata '{tool_name}' did not match ToolMetadata schema: {e}. Data: {response_data}")
            raise ValueError(f"MCP tool metadata invalid: {e}")
        except Exception as e:
            logger.error(f"Failed to get tool metadata for '{tool_name}': {e}")
            raise

    def list_tools(self) -> List[ToolMetadata]:
        """
        Lists all available tools and their metadata from MCP.
        """
        path = "/api/tools/metadata"
        try:
            response_data = self._make_request("GET", path)
            # Expecting a list of tool metadata objects
            return [ToolMetadata.model_validate(item) for item in response_data]
        except ValidationError as e:
            logger.error(f"MCP response for list_tools did not match List[ToolMetadata] schema: {e}. Data: {response_data}")
            raise ValueError(f"MCP list_tools response invalid: {e}")
        except Exception as e:
            logger.error(f"Failed to list tools from MCP: {e}")
            return []