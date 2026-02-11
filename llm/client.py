"""
llm/client.py: Handles communication with the local LLM (Ollama via OpenAI-compatible API).
"""

import json
import requests
import logging
from typing import Dict, Any

from config.settings import settings
from schemas.action import LLMRawActionOutput # Import the Pydantic model for validation
from pydantic import ValidationError

logger = logging.getLogger(__name__)

class LLMClient:
    """
    Client for interacting with the local LLM (e.g., Ollama's OpenAI-compatible API).
    Ensures that LLM responses adhere to the defined LLMRawActionOutput schema.
    """
    def __init__(self):
        self.base_url = settings.LLM_BASE_URL
        self.model_name = settings.LLM_MODEL_NAME
        if not self.base_url or not self.model_name:
            raise ValueError("LLM_BASE_URL and LLM_MODEL_NAME must be configured.")
        logger.info(f"LLMClient initialized for model '{self.model_name}' at '{self.base_url}'")

    def _call_api(self, messages: list, response_format: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Internal method to make a call to the LLM API endpoint.
        """
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": 0.0,  # Keep output deterministic for decision-making
            "response_format": response_format or {"type": "json_object"}
        }
        
        try:
            # OpenAI-compatible API usually uses /chat/completions
            response = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload, timeout=settings.LLM_TIMEOUT_SECONDS)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.Timeout:
            logger.error(f"LLM API call timed out after {settings.LLM_TIMEOUT_SECONDS} seconds.")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with LLM API at {self.base_url}: {e}")
            raise

    def get_action(self, system_prompt: str, user_prompt: str) -> LLMRawActionOutput:
        """
        Queries the LLM for an action and validates its output against the LLMRawActionOutput schema.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        # Instruct the LLM to output JSON and provide the schema directly
        json_schema_instruction = (
            "\nYou MUST respond with a JSON object that strictly adheres to the following Pydantic schema.\n"
            "Do NOT include any other text, explanations, or formatting outside the JSON object.\n"
            "Schema:\n"
            f"{json.dumps(LLMRawActionOutput.model_json_schema(), indent=2)}"
        )
        messages[0]["content"] += json_schema_instruction

        try:
            llm_response_raw = self._call_api(messages)
            
            # Extract content, which should be the JSON string
            content_str = llm_response_raw['choices'][0]['message']['content']
            
            # Attempt to parse the content string as JSON
            action_data = json.loads(content_str)
            
            # Validate the parsed JSON against the Pydantic model
            return LLMRawActionOutput.model_validate(action_data)
            
        except (KeyError, IndexError) as e:
            logger.error(f"LLM response structure unexpected: {e}. Raw response: {llm_response_raw}")
            raise ValueError(f"LLM response structure unexpected: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"LLM response was not valid JSON: {e}. Content: {content_str}")
            raise ValueError(f"LLM response was not valid JSON: {e}")
        except ValidationError as e:
            logger.error(f"LLM response did not match the required schema: {e}. Data: {action_data}")
            raise ValueError(f"LLM response did not match the required schema: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while getting LLM action: {e}", exc_info=True)
            raise