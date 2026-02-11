import time
import logging

from agent.config import config
from agent.llm_interface import LLMInterface
from agent.mcp_client import MCPClient
from agent.state_manager import StateManager
from agent.planner import Planner
from agent.models import ToolExecutionAction, StateUpdateAction, ReportGenerationAction

# Configure logging
logging.basicConfig(level=config.LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def agent_loop(objective: str, initial_target: str):
    """
    Main execution loop for the LocalStrike agent.
    """
    llm_interface = LLMInterface()
    mcp_client = MCPClient()
    state_manager = StateManager()
    planner = Planner()

    state_manager.initialize(objective, initial_target)

    # Initial health check of MCP
    if not mcp_client.check_health():
        logger.error("HexStrike MCP is not healthy. Exiting agent.")
        return

    logger.info(f"Agent starting for objective: '{objective}' on target: '{initial_target}'")

    try:
        while not state_manager.is_objective_met():
            current_state = state_manager.get_current_state()
            logger.debug(f"Current State: {current_state}")

            # 1. Observe & Orient: Get LLM's next action
            system_prompt, user_prompt = planner.create_llm_prompt(current_state)
            
            try:
                llm_action_schema = llm_interface.get_llm_action(system_prompt, user_prompt)
                logger.info(f"LLM Thought: {llm_action_schema.thought} (Confidence: {llm_action_schema.confidence:.2f})")
            except ValueError as e:
                logger.error(f"LLM returned invalid action or schema mismatch: {e}. Retrying in {config.AGENT_LOOP_DELAY_SECONDS}s.")
                time.sleep(config.AGENT_LOOP_DELAY_SECONDS)
                continue # Skip to next loop iteration

            # 2. Act: Execute the action based on LLM's decision
            action = llm_action_schema.action
            
            if isinstance(action, ToolExecutionAction):
                logger.info(f"Executing tool: {action.tool_name} with parameters: {action.parameters}")
                try:
                    task_id = mcp_client.execute_tool(action.tool_name, action.parameters)
                    state_manager.add_pending_task(task_id, llm_action_schema)
                except Exception as e:
                    logger.error(f"Failed to execute tool {action.tool_name}: {e}. Continuing...")
            
            elif isinstance(action, StateUpdateAction):
                logger.info(f"Updating internal state: {action.instruction}")
                state_manager.update_internal_state(action.instruction)
            
            elif isinstance(action, ReportGenerationAction):
                logger.info("LLM requested report generation. Marking objective met.")
                final_report_data = planner.generate_final_report(current_state)
                state_manager.save_report(final_report_data)
                state_manager.mark_objective_met()
            
            # 3. Review: Check for completed tasks and update state
            pending_tasks = state_manager.get_pending_tasks()
            if pending_tasks:
                logger.debug(f"Checking {len(pending_tasks)} pending tasks...")
                tasks_to_check = list(pending_tasks.keys())
                for task_id in tasks_to_check:
                    try:
                        # Fetch result for each pending task
                        tool_result = mcp_client.get_task_result(task_id)
                        if tool_result.status != "PENDING": # Task is no longer pending
                            state_manager.process_tool_result(tool_result)
                    except Exception as e:
                        logger.warning(f"Could not retrieve result for task {task_id}: {e}. Retrying later.")
            else:
                logger.debug("No pending tasks to check.")
            
            if not state_manager.is_objective_met():
                time.sleep(config.AGENT_LOOP_DELAY_SECONDS)

    except KeyboardInterrupt:
        logger.warning("Agent interrupted by user.")
    except Exception as e:
        logger.critical(f"An unhandled error occurred in the agent loop: {e}", exc_info=True)
    finally:
        logger.info("Agent finished or terminated.")
        return state_manager.get_final_report()

if __name__ == "__main__":
    # Example usage:
    # This should ideally come from CLI arguments or a config file
    initial_objective = "Perform subdomain enumeration and port scanning on the target."
    initial_target_url = "example.com" # Replace with a real target for testing

    final_report = agent_loop(initial_objective, initial_target_url)
    if final_report:
        logger.info(f"Assessment completed. Final Report: {final_report}")
    else:
        logger.info("Assessment did not complete or no report generated.")
