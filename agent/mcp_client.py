import requests
import time
from typing import Dict, Any, Optional, List

from agent.config import config
from agent.models import ToolResult # Assuming ToolResult model exists for response validation

class MCPClient:
    """
    Client for interacting with the HexStrike Mission Control Platform (MCP) API.
    """
    def __init__(self):
        self.base_url = config.MCP_BASE_URL
        if not self.base_url.startswith("http"):
            raise ValueError(f"MCP_BASE_URL must be a valid URL, got: {self.base_url}")

    def _make_request(self, method: str, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Helper method to make HTTP requests to the MCP.
        """
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.request(method, url, headers=headers, json=json_data, timeout=300)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error communicating with MCP API at {url}: {e}")
            raise

    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        Sends a request to MCP to execute a specific security tool.
        Returns the task_id if the execution request was successful.
        """
        path = f"/api/tools/{tool_name}"
        try:
            response = self._make_request("POST", path, json_data=parameters)
            # Assuming MCP returns a task_id in its response for async execution
            if "task_id" in response:
                return response["task_id"]
            else:
                raise ValueError(f"MCP did not return a 'task_id' for tool '{tool_name}'. Response: {response}")
        except Exception as e:
            print(f"Failed to execute tool '{tool_name}': {e}")
            raise

    def get_task_result(self, task_id: str) -> ToolResult:
        """
        Retrieves the result of an asynchronously executed task from MCP.
        """
        path = f"/api/process/get-task-result/{task_id}"
        try:
            response = self._make_request("GET", path)
            return ToolResult.model_validate(response)
        except Exception as e:
            print(f"Failed to get result for task '{task_id}': {e}")
            raise

    def check_health(self) -> bool:
        """
        Checks the health endpoint of the MCP.
        """
        path = "/health"
        try:
            response = self._make_request("GET", path)
            return response.get("status") == "healthy"
        except Exception as e:
            print(f"MCP Health check failed: {e}")
            return False

    def list_running_processes(self) -> List[Dict[str, Any]]:
        """
        Lists currently running processes on the MCP.
        """
        path = "/api/processes/list"
        try:
            response = self._make_request("GET", path)
            return response.get("processes", [])
        except Exception as e:
            print(f"Failed to list running processes: {e}")
            return []
