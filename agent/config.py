import os
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env file

class Config:
    """
    Configuration settings for the LocalStrike agent.
    Loads values from environment variables.
    """
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
    LLM_MODEL_NAME: str = os.getenv("LLM_MODEL_NAME", "llama3")

    MCP_BASE_URL: str = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8888")

    AGENT_LOOP_DELAY_SECONDS: int = int(os.getenv("AGENT_LOOP_DELAY_SECONDS", "5"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

config = Config()
