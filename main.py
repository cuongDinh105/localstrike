"""
LocalStrike: Main entry point for the AI penetration testing agent.
"""

import logging
import sys

# Ensure localstrike package is in path for imports
sys.path.insert(0, './')

from agent.agent import LocalStrikeAgent
from config.settings import settings

# Configure basic logging
logging.basicConfig(level=settings.LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """
    Initializes and runs the LocalStrike AI agent.
    """
    logger.info("Starting LocalStrike AI Agent...")
    
    # TODO: Implement argument parsing for objective and target
    objective = "Perform comprehensive reconnaissance on the target."
    target = "example.com" # Placeholder, should come from user input

    agent = LocalStrikeAgent(objective=objective, target=target)
    
    try:
        final_report = agent.run()
        if final_report:
            logger.info("Agent run completed. Final report generated.")
            # TODO: Add logic to save or display the final report
            # print(final_report)
        else:
            logger.warning("Agent run completed, but no final report was generated.")
    except Exception as e:
        logger.critical(f"An unhandled error occurred during agent execution: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("LocalStrike AI Agent stopped.")

if __name__ == "__main__":
    main()
