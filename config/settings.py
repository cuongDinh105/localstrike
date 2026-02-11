"""
config/settings.py: Manages application configuration using environment variables.
"""

import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    """
    Configuration settings for the LocalStrike agent, loaded from environment variables.
    """
    # General Agent Settings
    AGENT_LOOP_DELAY_SECONDS: int = int(os.getenv("AGENT_LOOP_DELAY_SECONDS", "5"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    DEBUG_MODE: bool = os.getenv("DEBUG_MODE", "False").lower() in ('true', '1', 't')

    # LLM Configuration
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
    LLM_MODEL_NAME: str = os.getenv("LLM_MODEL_NAME", "llama3")
    LLM_TIMEOUT_SECONDS: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "300")) # 5 minutes

    # HexStrike Mission Control Platform (MCP) Configuration
    MCP_BASE_URL: str = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8888")
    MCP_TIMEOUT_SECONDS: int = int(os.getenv("MCP_TIMEOUT_SECONDS", "120")) # 2 minutes

    # State & Memory Settings (Part 1, 2, 3)
    MAX_AGENT_ITERATIONS: int = int(os.getenv("MAX_AGENT_ITERATIONS", "100"))
    MAX_AGENT_RUNTIME_SECONDS: int = int(os.getenv("MAX_AGENT_RUNTIME_SECONDS", "3600")) # 1 hour
    
    # Repetition detection
    REPETITION_HISTORY_LENGTH: int = int(os.getenv("REPETITION_HISTORY_LENGTH", "5")) # How many recent actions to track
    REPETITION_MIN_SEQUENCE_LENGTH: int = int(os.getenv("REPETITION_MIN_SEQUENCE_LENGTH", "2")) # Min length of sequence to detect
    REPETITION_SEQUENCE_PENALTY: int = int(os.getenv("REPETITION_SEQUENCE_PENALTY", "3")) # no_progress_count penalty for sequence repetition

    # Failure handling
    TOOL_FAILURE_THRESHOLD: int = int(os.getenv("TOOL_FAILURE_THRESHOLD", "3")) # How many times a tool can fail on a target before blocking
    FAILURE_PENALTY: int = int(os.getenv("FAILURE_PENALTY", "1")) # no_progress_count penalty for a failed action

    # No Progress Detection (Part 4)
    NO_PROGRESS_THRESHOLD: int = int(os.getenv("NO_PROGRESS_THRESHOLD", "5")) # Soft signal to LLM
    MAX_NO_PROGRESS_COUNT: int = int(os.getenv("MAX_NO_PROGRESS_COUNT", "15")) # Hard stop if no progress for this many iterations

    # Human-in-the-Loop (HITL) Settings
    NO_PROGRESS_THRESHOLD_FOR_APPROVAL: int = int(os.getenv("NO_PROGRESS_THRESHOLD_FOR_APPROVAL", "3")) # If no progress for this many iterations, require approval

    # Scope Enforcement Engine Settings
    DEFAULT_SCOPE_MAX_DEPTH: int = int(os.getenv("DEFAULT_SCOPE_MAX_DEPTH", "3")) # Default max_depth for scope if not specified

    # LLM Context Summarization (Part 3)
    LLM_EXAMPLE_PORTS_COUNT: int = int(os.getenv("LLM_EXAMPLE_PORTS_COUNT", "3"))
    LLM_EXAMPLE_SERVICES_COUNT: int = int(os.getenv("LLM_EXAMPLE_SERVICES_COUNT", "3"))
    LLM_EXAMPLE_TECH_COUNT: int = int(os.getenv("LLM_EXAMPLE_TECH_COUNT", "3"))
    LLM_EXAMPLE_ASSETS_COUNT: int = int(os.getenv("LLM_EXAMPLE_ASSETS_COUNT", "5"))
    LLM_RECENT_ACTIONS_COUNT: int = int(os.getenv("LLM_RECENT_ACTIONS_COUNT", "5"))
    LLM_RECENT_FINDINGS_COUNT: int = int(os.getenv("LLM_RECENT_FINDINGS_COUNT", "3"))
    LLM_FAILED_ACTION_THRESHOLD: int = int(os.getenv("LLM_FAILED_ACTION_THRESHOLD", "1")) # For LLM summary: show tools that failed >= this count
    LLM_RECENT_RISK_SIGNALS_COUNT: int = int(os.getenv("LLM_RECENT_RISK_SIGNALS_COUNT", "3"))


# Instantiate settings
settings = Settings()

# Set up logging based on configuration
logging.basicConfig(level=settings.LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if settings.DEBUG_MODE:
    logging.getLogger(__name__).setLevel(logging.DEBUG)