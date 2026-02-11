# LocalStrike: Autonomous AI Penetration Testing Agent

LocalStrike is a cutting-edge, fully local AI-powered penetration testing orchestration system designed for robust, auditable, and safe security assessments. It empowers security professionals to conduct autonomous pentests with a strong emphasis on control, traceability, and deterministic enforcement layers.

---

## 🚀 Project Overview

LocalStrike stands at the forefront of AI-driven security. By leveraging a local-first architecture, it ensures sensitive data remains within your control, adhering to strict compliance and privacy requirements. The agent's decision-making is powered by a local Large Language Model (LLM), meticulously guided by a hierarchy of deterministic security layers, an independent Reviewer Agent, and essential Human-in-the-Loop (HITL) intervention points.

**Key Features & Properties:**

*   **Local-First AI**: Utilizes Ollama-compatible LLMs, eliminating reliance on external cloud AI services.
*   **Deterministic Security Layers**: A multi-layered defense mechanism ensures actions are strictly within scope and risk boundaries.
*   **Human-in-the-Loop (HITL)**: Critical and high-risk actions require explicit human approval, providing ultimate oversight.
*   **Comprehensive Auditability**: Every decision, action, and outcome is meticulously logged with unique IDs for full traceability.
*   **JSON Schema Validation**: Strict validation for all tool parameters and outputs, preventing injection and corruption.
*   **Asset Relationship Graph**: Dynamically builds and maintains a graph of discovered assets, enabling semantic validation of targets.
*   **Evidence Integrity**: Raw tool outputs are hashed and referenced, ensuring tamper-evident proof for findings.
*   **Production-Grade Reporting**: Generates professional, detailed pentest reports in both human-readable (Markdown) and machine-readable (JSON) formats.
*   **Adversarial Hardening**: Built-in safeguards against LLM misbehavior, tool output corruption, and loop-based attacks.

---

## 📐 Architecture Overview

LocalStrike's architecture is designed for modularity, security, and scalability, emphasizing clear separation of concerns and deterministic control.

```
+------------------+     +--------------------------+
|  USER (CLI)      |<---->|  Human-in-the-Loop (HITL)|
+------------------+     +--------------------------+
          ^                       | Approved/Modified Actions
          |                       | Rejected/Aborted Signals
          |                       V
+-----------------------------------------------------+
| LocalStrike Agent (Primary Orchestrator)            |
+-----------------------------------------------------+
|  1. LLM Prompting & Action Generation               |
|  2. LLM Raw Output Parsing & Internal Action Conv.  |
|  3. [NEW] ScopeEngine Validation <--------------------+ (Reads ScopeDefinition)
|  4. [NEW] Reviewer Agent Review   <-----------------+ (Reads State, Tool Metadata)
|  5. [NEW] Human Approval Gate     <----------------+ (Interacts with User)
|  6. MCP Tool Execution / State Update / Report Gen.  |
|  7. Task Management & State Update                  |
|  8. Loop Control & Termination Logic                |
+--------------------^--------------------v-----------+
                     |                    |
+--------------------+--------------------+---------------------+
| StateManager (Single Source of Truth)   | AssetGraphEngine     |
| - Objective & Scope                     | - Asset Nodes        |
| - Asset Discovery (from Graph)          | - Relationships      |
| - Attack Surface Mapping                | - Depth Calculation  |
| - Findings & Evidence                   | - Semantic Validation|
| - Executed Actions Log                  |                      |
| - Pending MCP Tasks                     |                      |
| - Failed / Blocked Actions              |                      |
| - Risk Signals                          |                      |
| - Termination Conditions                |                      |
+-----------------------------------------+----------------------+
                     ^                    |
                     |                    |
+--------------------+--------------------+---------------------+
| MCP Client (HTTP)  |   ReportEngine     |                     |
|                    |<-------------------|                     |
| - Tool Metadata    |                    |                     |
| - Tool Execution   |                    |                     |
| - Task Results     |                    |                     |
+--------------------+--------------------+---------------------+
                     v
             +---------------------+
             | HexStrike MCP (TaaS)|
             | (Tools as a Service)|
             +---------------------+
```

---

## 🧩 Component Breakdown

| Component              | Responsibility                                                                | Key Functionality                                                |
| :--------------------- | :---------------------------------------------------------------------------- | :--------------------------------------------------------------- |
| **Primary Agent**      | Orchestrates the entire pentest, plans actions using LLM.                     | LLM prompting, action parsing, orchestrates execution lifecycle. |
| **Reviewer Agent**     | Independent, non-executing validation of proposed actions.                    | Assesses risk, redundancy, scope; returns `approve`/`caution`/`block` feedback. |
| **ScopeEngine**        | Deterministic enforcement of engagement boundaries.                           | Validates targets against domains, IPs, exclusions, depth, and semantic rules. |
| **HITL Layer**         | Provides human oversight and intervention points.                             | Pauses execution, presents action details, processes human decisions (approve, reject, modify, abort). |
| **MCP Client**         | Secure communication interface with HexStrike MCP.                            | Fetches tool metadata, executes tools, retrieves task results.   |
| **StateManager**       | Centralized repository for all assessment data.                               | Stores objective, assets, findings, executed actions, handles persistence. |
| **AssetGraphEngine**   | Dynamically builds and queries a graph of assets and their relationships.     | Inferred asset types, computes depth, handles DNS resolution drift. |
| **ReportEngine**       | Transforms internal state into structured pentest reports.                    | Correlates findings/evidence, risk scoring, generates JSON/Markdown reports. |
| **Local LLM**          | Provides planning and reasoning capabilities.                                 | Generates `LLMRawActionOutput` based on prompts (Ollama-compatible). |

---

## 🏃 Execution Flow: An Iteration Lifecycle

LocalStrike operates in an iterative loop, constantly observing the state, deciding the next best action, and executing it, all while passing through a series of robust security and control gates:

1.  **Read Persisted State**: At the start of each iteration, the `StateManager` loads the latest assessment state from disk.
2.  **Build LLM-Visible Memory Snapshot**: `StateManager` generates a summarized, sanitized view of the current assessment state for the LLM, adhering to strict visibility rules and summarization thresholds.
3.  **Generate Planning Prompt**: The Primary Agent constructs a detailed prompt, including the objective, current state snapshot, and available tool metadata (including their JSON schema), and sends it to the Local LLM.
4.  **Receive LLM Raw Output**: The LLM responds with a `LLMRawActionOutput` (JSON object) detailing its proposed action, parameters, and reason.
5.  **Validate & Convert to Internal Action**: The Primary Agent validates the LLM's raw output against `LLMRawActionOutput` schema, performs tool allow-listing, validates proposed parameters against the tool's JSON schema, and converts it into a rich `LLMInternalAction` object.
6.  **Log Proposed Action**: The `StateManager` logs the `LLMInternalAction` with a `PROPOSED` status, assigning a unique `action_id`.
7.  **[NEW] Scope Enforcement Check**:
    *   The `ScopeEngine` performs deterministic validation (`ScopeEngine.validate_action`) of the `LLMInternalAction` against the defined scope boundaries, using the `AssetGraphEngine` for semantic checks (depth, IP ranges, excluded assets, DNS resolution drift).
    *   **IF `NOT is_allowed`**: The action is immediately blocked. Its status is updated to `SCOPE_BLOCKED` in `StateManager`, and the agent skips execution, forcing the LLM to replan. **Scope is the ultimate enforcer.**
8.  **[NEW] Reviewer Agent Feedback**:
    *   The `ReviewerAgent` receives the `LLMInternalAction` and a copy of the LLM-visible state. It uses its own LLM to assess risks, redundancies, and scope adherence, returning `ReviewerFeedback` (approve/caution/block).
    *   **IF `ReviewerFeedback.review_decision == "block"`**: The action is blocked. Its status is updated to `REVIEW_BLOCKED` in `StateManager`, and the agent skips execution, forcing the LLM to replan.
9.  **[NEW] Human-in-the-Loop (HITL) Approval Gate**:
    *   A deterministic policy (`_determine_approval_level`) assesses the `LLMInternalAction` (including its risk, sensitivity, and `ReviewerFeedback`) to decide if human intervention is `REQUIRED`.
    *   **IF `approval_required`**: The agent pauses, logs `WAITING_FOR_APPROVAL`, and presents the action details (including Reviewer Feedback and Scope check result) to the user via CLI. The user can then `approve`, `reject`, `modify` parameters, or `abort` the mission.
    *   User decisions are logged with unique IDs. If parameters are modified, a new `LLMInternalAction` is generated and logged.
10. **Execute Approved Action**:
    *   If the action passes all gates, the Primary Agent executes it:
        *   **Tool Execution**: `MCPClient` is called to execute the tool via HexStrike MCP. The action status is updated to `EXECUTING`, and a `mcp_task_id` is recorded.
        *   **State Update**: `StateManager`'s `update_internal_state` method is invoked.
        *   **Report Generation**: `StateManager` triggers the `ReportEngine`.
11. **Process Tool Results**: For executed tools, the agent periodically checks `MCPClient` for `ToolResult`.
    *   Upon completion, `StateManager.process_tool_result` updates the relevant `ExecutedAction` entry (status, end time, error), and updates asset discovery, attack surface mapping, and findings based on the structured `ToolOutput`.
12. **Check Loop Control & Termination**: `StateManager.is_objective_met` evaluates conditions like `max_iterations`, `max_runtime`, `no_progress_count`, and `blocked_assets` to decide if the mission should continue or terminate.
13. **Persist Updated State**: The `StateManager` saves the entire assessment state to disk, enabling auditability and resumability.
14. **Repeat or Terminate**: The loop continues until `is_objective_met` returns `True`.

---

## 🛡️ Security Layers Explained

LocalStrike employs a hierarchical, multi-layered security model where each layer provides deterministic enforcement, enhancing the overall robustness and safety of autonomous operations.

1.  **ScopeEngine (Ultimate Enforcer)**:
    *   **Purpose**: Prevents any action from targeting assets outside the defined engagement scope.
    *   **Mechanism**: Deterministically checks proposed actions against `allowed_domains`, `allowed_ip_ranges`, `excluded_assets`, and `max_depth`. Integrates with `AssetGraphEngine` for semantic validation (DNS resolution drift, asset lineage).
    *   **Priority**: Highest. Blocks actions *before* Reviewer or Human involvement.

2.  **Reviewer Agent (Independent Validator)**:
    *   **Purpose**: Provides an independent, LLM-driven sanity check on the Primary Agent's proposals.
    *   **Mechanism**: Uses its own LLM to review the proposed `LLMInternalAction` and current state. Returns `approve`/`caution`/`block` feedback.
    *   **Priority**: High. A `block` decision from the Reviewer forces the Primary Agent to re-plan, even if other layers might have permitted the action.

3.  **Human-in-the-Loop (HITL) (Ultimate Oversight)**:
    *   **Purpose**: Provides explicit human approval for high-risk or uncertain actions.
    *   **Mechanism**: A deterministic policy (`_determine_approval_level`) flags actions based on `tool_metadata.risk_level`, `output_sensitivity`, `ReviewerFeedback`, and critical state warnings. Pauses agent execution for human interaction.
    *   **Priority**: High. No action flagged for human approval can proceed without explicit human consent or modification.

4.  **Tool Interface Contract (Input/Output Hardening)**:
    *   **Purpose**: Ensures safe and predictable interaction with external pentesting tools.
    *   **Mechanism**: Strict JSON Schema validation for tool parameters (client-side and MCP-side), standardized `ToolOutput` with `summary`, `assets_found`, `findings`, and `raw_output_ref`. Unified `ToolError` model. Prevents output poisoning and ensures data integrity.

5.  **Loop Control & Adversarial Protection**:
    *   **Purpose**: Safeguards against infinite loops, resource abuse, and agent getting stuck.
    *   **Mechanism**: `max_iterations`, `max_runtime`, `no_progress_count`, `repeated_action_detection`, `dead-end detection`. Ensures graceful termination and logging of problematic behaviors.

---

## 📦 Installation Guide (Linux)

To get LocalStrike up and running on your Linux system:

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/cuongDinh105/localstrike.git
    cd localstrike
    ```

2.  **Install Python Dependencies**:
    It's recommended to use a Python virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Environment Configuration**:
    Copy the example environment file and then edit it with your specific settings.
    ```bash
    cp .env.example .env
    ```
    **Edit the `.env` file**:

    *   **LLM Provider (Ollama)**:
        ```ini
        LLM_BASE_URL="http://localhost:11434/v1" # Your Ollama endpoint
        LLM_MODEL_NAME="llama3" # The LLM model LocalStrike will use for planning (e.g., llama3, codellama)
        LLM_TIMEOUT_SECONDS=300
        ```
        Ensure Ollama is running and the specified model is pulled.

    *   **HexStrike MCP Endpoint**:
        ```ini
        MCP_BASE_URL="http://127.0.0.1:8888" # Your HexStrike Mission Control Platform API endpoint
        MCP_TIMEOUT_SECONDS=120
        ```
        LocalStrike relies on an external HexStrike MCP instance for tool execution. Ensure it's running and accessible.

    *   **Scope Definition**:
        ```ini
        # Define the maximum depth the agent can explore from the initial target
        DEFAULT_SCOPE_MAX_DEPTH=3 
        ```
        (More detailed scope configuration for `allowed_domains`, `allowed_ip_ranges`, `excluded_assets` will be passed via CLI arguments or a dedicated scope file in future iterations, but `DEFAULT_SCOPE_MAX_DEPTH` provides a sensible initial limit.)

    *   **Safety Thresholds**:
        ```ini
        MAX_AGENT_ITERATIONS=100      # Hard stop after this many planning-execution cycles
        MAX_AGENT_RUNTIME_SECONDS=3600 # Hard stop after 1 hour (3600 seconds)
        NO_PROGRESS_THRESHOLD_FOR_APPROVAL=3 # If no progress for 3 iterations, prompt human approval for next action
        TOOL_FAILURE_THRESHOLD=3      # Mark asset as blocked after 3 consecutive failures of a tool on it
        REPETITION_HISTORY_LENGTH=5   # Number of past actions to check for repetition
        # ... other settings ...
        ```
        Adjust these thresholds to control the agent's autonomy and aggressiveness.

---

## ⚙️ Environment Configuration (`.env` Explanation)

The `.env` file is crucial for configuring LocalStrike's behavior without modifying source code.

*   `LLM_BASE_URL`: The API endpoint of your local LLM server (e.g., Ollama's OpenAI-compatible API).
*   `LLM_MODEL_NAME`: The specific model LocalStrike should use (e.g., `llama3`, `codellama`).
*   `LLM_TIMEOUT_SECONDS`: Timeout for LLM API calls.
*   `MCP_BASE_URL`: The API endpoint of your HexStrike Mission Control Platform.
*   `MCP_TIMEOUT_SECONDS`: Timeout for MCP API calls.
*   `AGENT_LOOP_DELAY_SECONDS`: Delay between agent iterations to prevent busy-looping.
*   `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL).
*   `DEBUG_MODE`: Enables verbose debugging and re-raises critical exceptions.
*   `MAX_AGENT_ITERATIONS`: Limits the total number of agent decision loops.
*   `MAX_AGENT_RUNTIME_SECONDS`: Limits the total execution time of the agent.
*   `REPETITION_HISTORY_LENGTH`, `REPETITION_MIN_SEQUENCE_LENGTH`, `REPETITION_SEQUENCE_PENALTY`: Control detection of repeated actions.
*   `TOOL_FAILURE_THRESHOLD`, `FAILURE_PENALTY`: Manage how persistent tool failures impact progress tracking.
*   `NO_PROGRESS_THRESHOLD`, `MAX_NO_PROGRESS_COUNT`: Define thresholds for detecting and acting on lack of progress.
*   `NO_PROGRESS_THRESHOLD_FOR_APPROVAL`: Activates HITL for actions if the agent is stuck for too long.
*   `LLM_EXAMPLE_PORTS_COUNT`, `LLM_RECENT_ACTIONS_COUNT`, etc.: Control the level of detail summarized for the LLM's context window.

---

## 场景分析 ➡️ Example Usage Scenario

Let's walk through a hypothetical scenario:

**Objective**: Perform reconnaissance on `example.com`.
**Scope**: `example.com`, `max_depth=2`.

1.  **LLM Proposal**: LLM suggests `tool_name: subfinder`, `parameters: {"target": "example.com"}`, `reason: "Discover subdomains."`.
2.  **ScopeEngine**: `subfinder` on `example.com` is `in-scope` (initial target, depth 0). **ALLOWED**.
3.  **Reviewer Agent**: Reviews `subfinder` action. Returns `review_decision: "approve"`, `review_reason: "Standard reconnaissance, low risk."`.
4.  **HITL Layer**: `subfinder` is `low-risk`, `recon` category, `auto-approved`.
5.  **Execution**: `MCPClient` calls `subfinder`.
6.  **Tool Output**: `subfinder` returns `dev.example.com` and `internal.example.com`.
7.  **StateManager**: Updates `AssetGraphEngine` with new subdomains, `dev.example.com` is `depth 1`, `internal.example.com` is `depth 1`.
8.  **LLM Proposal (next iteration)**: LLM suggests `tool_name: nmap`, `parameters: {"target": "dev.example.com", "ports": "top-1000"}`, `reason: "Scan for open ports on discovered subdomain."`.
9.  **ScopeEngine**: `nmap` on `dev.example.com` is `in-scope` (depth 1, within `max_depth=2`). **ALLOWED**.
10. **Reviewer Agent**: Reviews `nmap` action. Returns `review_decision: "caution"`, `review_reason: "Medium risk scanning activity, proceed with care."`.
11. **HITL Layer**: `nmap` is `medium-risk`, `scanning` category, and `ReviewerAgent` gave "caution". `_determine_approval_level` determines `REQUIRES_HUMAN_APPROVAL`.
12. **Agent Pauses**: Presents action details (Nmap on dev.example.com, Reviewer caution) to the user via CLI.
13. **Human Decision**: User approves (`a`).
14. **Execution**: `MCPClient` calls `nmap`.
15. **Tool Output**: `nmap` returns open ports (80, 443) for `dev.example.com`.
16. **LLM Proposal (next iteration)**: LLM suggests `tool_name: sqlmap`, `parameters: {"target": "dev.example.com/login", "data": "username=test"}`, `reason: "Check for SQL Injection on login."`.
17. **ScopeEngine**: `sqlmap` on `dev.example.com/login` is `in-scope` (depth 2). **ALLOWED**.
18. **Reviewer Agent**: Reviews `sqlmap`. Returns `review_decision: "block"`, `review_reason: "High risk direct exploitation attempt not suitable for initial recon phase."`.
19. **Agent BLOCKS Action**: `ReviewerAgent`'s "block" overrides. Agent logs `REVIEW_BLOCKED`. Agent skips execution, LLM will replan.
20. **LLM Proposal (next iteration)**: LLM, seeing `sqlmap` blocked, proposes `tool_name: update_state`, `parameters: {"instruction": "Focus on the next asset available."}`, `reason: "Change focus after failed exploitation attempt."`.
21. **ScopeEngine**: `update_state` is `internal` command, always in scope. **ALLOWED**.
22. **Reviewer Agent**: `update_state` is `internal`, `low-risk`. `review_decision: "approve"`.
23. **HITL Layer**: `update_state` is `low-risk`, `auto-approved`.
24. **Execution**: `StateManager` updates `current_focus_asset`.

---

## 🗺️ Scope Configuration Example

The scope of an assessment is defined through the `ScopeDefinition` object, which currently can be customized via the `initial_target` and parameters in `config/settings.py`.

Example default `ScopeDefinition` (defined in `agent/agent.py` `__init__` for simplicity initially):

```python
# Assuming initial_target is "example.com"
self.scope_definition = ScopeDefinition(
    initial_target_value="example.com",
    allowed_domains=["example.com"],
    allowed_ip_ranges=[], # Could be ["192.168.1.0/24"]
    excluded_assets=["test.example.com", "192.168.1.10"],
    max_depth=settings.DEFAULT_SCOPE_MAX_DEPTH, # e.g., 3
    scan_intensity_level="medium"
)
```
*   `allowed_domains`: List of root domains. Subdomains of these are implicitly allowed.
*   `allowed_ip_ranges`: List of CIDR blocks (e.g., "10.0.0.0/8").
*   `excluded_assets`: Specific assets that are always out of scope, even if they would otherwise be allowed.
*   `max_depth`: The maximum number of "hops" (relationships in the AssetGraph) away from the `initial_target` the agent is allowed to explore.
*   `scan_intensity_level`: (Currently a hint, but can be used by `_determine_approval_level` or `ReviewerAgent` to adjust risk thresholds).

---

## 🤖 Reviewer & HITL Flow Explained

LocalStrike's multi-layered approval process ensures safety:

1.  **LLM Proposal**: The Primary Agent's LLM suggests an action.
2.  **ScopeEngine Block**: First, the `ScopeEngine` performs an automatic, deterministic check. If the action is out of scope, it's immediately blocked.
3.  **Reviewer Agent Scrutiny**: If in scope, the `ReviewerAgent` (an independent LLM) then provides an expert opinion:
    *   `approve`: The action appears safe and beneficial.
    *   `caution`: The action has some concerns but might be acceptable.
    *   `block`: The action is too risky, redundant, or a violation.
4.  **Human Approval Policy**: A deterministic policy within the Primary Agent (not the LLM) uses `tool_metadata.risk_level`, `output_sensitivity`, and the `ReviewerFeedback` to decide if human intervention is required.
    *   Actions with `high`/`critical` risk, `high` sensitivity, or `ReviewerFeedback` of "caution"/"block" typically trigger human approval.
    *   If `ReviewerFeedback` is "block", the action is blocked without human intervention, forcing LLM replanning.
5.  **Human Decision**: If approval is required, the agent pauses. The user is presented with the action's details (including Reviewer's reason) and can:
    *   **Approve**: Action proceeds.
    *   **Reject**: Action is discarded, LLM replans.
    *   **Modify**: Parameters are adjusted by the human, then the modified action proceeds.
    *   **Abort**: The entire mission is terminated.
6.  **Full Traceability**: All Reviewer Feedback and Human Decisions are recorded in the `StateManager`'s `ExecutedAction` log for complete auditability.

---

## 📊 Report Generation Explained

The `ReportEngine` transforms the rich, structured data within the `StateManager` into comprehensive pentest reports.

*   **When Generated**: Automatically upon mission completion/termination, or on manual request.
*   **Key Sections**: Engagement Metadata, Scope Definition, Methodology (derived from executed actions), Findings (sorted by severity, linked to evidence), Risk Assessment, Limitations, and Executive Summary inputs.
*   **Evidence Traceability**: Every finding is linked via `raw_output_ref` to its original, hashed tool output, stored securely by the MCP. This ensures tamper-evident proof.
*   **Deterministic Risk Scoring**: Finding severities are calculated based on a deterministic, rule-based scoring logic, not subjective LLM output.
*   **Output Formats**:
    *   **Machine-Readable (JSON)**: The full internal report data model, ideal for integration with other security platforms.
    *   **Human-Readable (Markdown/HTML Conceptual)**: A formatted report designed for human review, with prose and clear presentation (Markdown currently implemented as a basic template).

---

## 🔐 Security Model Explanation

LocalStrike is engineered with a "trust but verify" philosophy, where no single component (especially LLMs) is fully trusted to make critical security decisions autonomously.

*   **Layered Enforcement**: ScopeEngine > Reviewer Agent > Human-in-the-Loop form a robust hierarchy, ensuring actions are filtered multiple times for safety and compliance.
*   **Deterministic Safety**: All critical security decisions (scope validation, approval levels) are governed by explicit, non-LLM, deterministic code.
*   **LLM Containment**: LLMs are confined to planning and reasoning. They cannot directly execute tools, modify core state deterministically, or bypass safety mechanisms.
*   **Tool Output Hardening**: Strict JSON schema validation and `raw_output_ref` for evidence prevent prompt injection or data poisoning from malicious tool outputs.
*   **Asset Graph for Semantic Understanding**: The `AssetGraphEngine` provides a machine-readable, auditable understanding of asset relationships, crucial for preventing semantic scope creep.
*   **Full Audit Trail**: The `ExecutedAction` log captures the entire lifecycle of every proposed action, including LLM's thought, reviewer feedback, human decisions, and execution outcomes, providing an undeniable record for post-assessment analysis.

---

## ⚔️ Adversarial Hardening Overview

LocalStrike incorporates specific mechanisms to resist adversarial attacks and gracefully handle system failures:

*   **LLM Misbehavior Resilience**:
    *   Strict JSON schema validation of LLM output (`LLMRawActionOutput`).
    *   Tool allow-listing, rejecting any hallucinated tool names.
    *   Agent-side parameter validation (`ToolMetadata.parameters_schema`) before MCP call.
    *   Reviewer Agent acts as a second LLM-based sanity check.
*   **Tool Output Corruption Protection**:
    *   `ToolOutput` Pydantic model enforces a strict schema for MCP responses.
    *   `raw_output_ref` hashes ensure integrity of raw evidence; only processed/sanitized data is fed back into state.
*   **MCP Failure Handling**:
    *   Unified `ToolError` model with `is_retryable` flag.
    *   `StateManager` tracks failed actions (`failed_actions`) and blocks problematic assets (`blocked_assets`) after thresholds are met.
    *   `no_progress_count` penalizes repeated failures, preventing infinite retries.
*   **Loop Control & Safety**:
    *   Hard limits on `MAX_AGENT_ITERATIONS` and `MAX_AGENT_RUNTIME_SECONDS`.
    *   `REPETITION_HISTORY_LENGTH` and `REPETITION_MIN_SEQUENCE_LENGTH` detect planning loops and increment `no_progress_count`.
    *   `MAX_NO_PROGRESS_COUNT` provides a hard stop for dead-ends.
    *   Critical errors trigger `force_terminate`.
*   **Report Integrity**: `ReportEngine` operates solely on the hardened `StateManager` data, with deterministic risk scoring and evidence referencing, making it resistant to output manipulation.

---

## 📈 Development Roadmap

*   **Enhanced Scope Definition**: CLI arguments for `allowed_domains`, `allowed_ip_ranges`, `excluded_assets`. Support for dynamic scope adjustments during a mission.
*   **Advanced Tool Metadata**: Integration of CVSS scoring, exploit chain potential, and more granular preconditions/postconditions into `ToolMetadata`.
*   **Human-in-the-Loop UI**: Development of a simple web-based interface for easier human approval and mission monitoring.
*   **Dynamic Tool Onboarding**: Mechanism for MCP to dynamically inform the agent about new tools and their `ToolMetadata` without agent restart.
*   **Real-time Notification System**: Integration with messaging platforms (Slack, email) for HITL alerts and critical risk signals.
*   **Adaptive Strategy Adjustment**: LLM-driven adaptation to observed failures or blocked assets (beyond simple replanning).
*   **Multi-Agent Coordination**: Exploring roles for specialized agents beyond the Primary and Reviewer.
*   **Reporting Enhancements**: Generation of PDF reports, customizable templates, integration with common security reporting tools.

---

## 👋 Contributing Guidelines

We welcome contributions! Please refer to our `CONTRIBUTING.md` (coming soon) for details on how to get started, report bugs, or propose features.

---

## 📄 License

This project is licensed under the [LICENSE_PLACEHOLDER].

---

## ⚠️ Disclaimer

LocalStrike is an autonomous penetration testing agent designed for **educational purposes and authorized security assessments only**. It is a powerful tool and should only be used on systems where you have explicit permission to perform security testing. The developers and maintainers of LocalStrike are not responsible for any misuse or damage caused by this software. Always comply with legal and ethical guidelines.

---
