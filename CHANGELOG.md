# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-13

### Added
- **Multi-Operator Swarm (`lib/swarm-coordinator.js`)**: Autonomous orchestration of reconnaissance, scanner, exploiter, validator, and analyst operators.
- **Keyless & Multi-Provider LLM Support (`lib/llm-provider.js`)**: Universal LLM layer supporting Anthropic, OpenRouter, Venice, xAI Grok, OpenAI, local Ollama/vLLM endpoints, and Mock mode.
- **Strict Scope Containment (`lib/egress-scope.js`)**: Egress and target scope restriction with CIDR, localhost, and domain authorization gates.
- **Model Context Protocol (MCP) Server (`lib/mcp-server.js`)**: Stdio-based MCP server providing standardized vulnerability scanning and validation tools to external agent workflows.
- **8-Phase Security Engine**:
  - Live agentic vulnerability hunting with static and heuristic pattern matching.
  - Adversarial self-challenge phase with skeptical validator verification.
  - Report generator supporting structured JSON and Markdown outputs.
  - Sandbox execution validation for experimental dynamic verification.
- **Interactive Web Showcase & Research Arc**:
  - Interactive browser analysis of Claude Fable 5 & Claude Mythos Preview (`index.html`, `mythos-deep-dive.html`).
  - Structured benchmarks data (`benchmarks.json`) and complete event timeline (`timeline.json`).
- **Comprehensive Community & CI Infrastructure**:
  - CI workflows for Node 18.x, 20.x, and 22.x.
  - Full issue and PR templates, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `CODEOWNERS`.
  - GitHub Sponsors configuration (`.github/FUNDING.yml`).
