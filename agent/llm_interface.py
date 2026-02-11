import json
import requests
from typing import Dict, Any, Optional
from pydantic import ValidationError

from agent.config import config
from agent.models import LLMAction

class LLMInterface:
    """
    Handles communication with the local LLM (e.g., Ollama via OpenAI-compatible API).
    """
    def __init__(self):
        self.base_url = config.LLM_BASE_URL
        self.model_name = config.LLM_MODEL_NAME
        # Add a simple check for the base_url
        if not self.base_url.startswith("http"):
            raise ValueError(f"LLM_BASE_URL must be a valid URL, got: {self.base_url}")
        if not self.model_name:
            raise ValueError("LLM_MODEL_NAME cannot be empty.")

    def _call_llm_api(self, messages: list, response_format: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Internal method to make a call to the LLM API.
        """
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": 0.0, # Keep output deterministic
            "response_format": response_format or {"type": "json_object"}
        }
        try:
            # For OpenAI compatible APIs, the chat completions endpoint is usually /chat/completions
            response = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload, timeout=600)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error communicating with LLM API: {e}")
            raise

    def get_llm_action(self, system_prompt: str, user_prompt: str) -> LLMAction:
        """
        Queries the LLM for an action and validates its output against the LLMAction schema.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        # Ensure the LLM is instructed to output JSON
        json_format_instruction = (
            "You MUST respond with a JSON object that adheres to the following schema:
"
            f"{LLMAction.model_json_schema()}" # Pydantic v2 method for schema
            "
Do NOT include any other text or formatting in your response."
        )
        
        messages[0]["content"] += "
" + json_format_instruction

        llm_response = self._call_llm_api(messages)
        
        try:
            # Extract the content from the LLM's response
            content_str = llm_response['choices'][0]['message']['content']
            # Parse the content string as JSON
            action_data = json.loads(content_str)
            # Validate against the Pydantic model
            return LLMAction.model_validate(action_data)
        except (KeyError, IndexError) as e:
            raise ValueError(f"Unexpected LLM response structure: {e}
Response: {llm_response}")
        except json.JSONDecodeError as e:
            raise ValueError(f"LLM response was not valid JSON: {e}
Content: {content_str}")
        except ValidationError as e:
            raise ValueError(f"LLM response did not match the required schema: {e}
Data: {action_data}")

