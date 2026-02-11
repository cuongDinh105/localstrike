# LocalStrike: Local-first AI Penetration Testing Agent

This project aims to build a local-first AI penetration testing agent that performs autonomous security assessments.

## Core Design Principles
1. The AI agent is a **planner and decision-maker only**, not an executor.
2. All security tools (nmap, nuclei, subfinder, etc.) are exposed as HTTP APIs by a separate Mission Control Platform (MCP) at `http://127.0.0.1:8888`.
3. The agent communicates with MCP using structured JSON over REST.
4. The LLM must return STRICT JSON actions, never free text.
5. The system must be deterministic, auditable, and safe.

## Architecture
- **Local LLM**: Ollama (e.g. llama3.1, codellama) for planning and reasoning.
- **Agent runtime**: Python.
- **Tool execution**: HexStrike MCP (Tools-as-a-Service) via REST APIs.
- **State**: In-memory first (can be extended later for persistence).

## Project Structure
- `agent/`: Core agent logic (main, config, LLM/MCP interfaces, state management, planner, models).
- `tests/`: Unit and integration tests.
- `docs/`: Project documentation.
- `config/`: Configuration files.

## Setup and Installation
(To be filled out during implementation)

## Usage
(To be filled out during implementation)

## Development
(To be filled out during implementation)