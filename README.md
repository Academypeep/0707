# Mythos Agent & The Fable 5 Arc

[![CI](https://github.com/Academypeep/0707/actions/workflows/ci.yml/badge.svg)](https://github.com/Academypeep/0707/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](package.json)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub_Sponsors-ff69b4.svg)](https://github.com/sponsors/Academypeep)

> **Autonomous multi-operator security vulnerability scanner swarm & research portal.**
> Implements an 8-phase vulnerability discovery scaffold with keyless LLM provider support, strict scope containment, MCP server integration, and the complete Claude Fable 5 / Mythos research arc.

🌐 **[View Live Research Website →](https://nraj-dataanalytics.github.io/Claude-Fable-5-Analysis/)**

---

## Table of Contents

- [Overview](#overview)
- [Architecture & 8-Phase Discovery Scaffold](#architecture--8-phase-discovery-scaffold)
- [Multi-Operator Autonomous Swarm](#multi-operator-autonomous-swarm)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Model Context Protocol (MCP) Server](#model-context-protocol-mcp-server)
- [Running Tests](#running-tests)
- [The Fable 5 Research Arc](#the-fable-5-research-arc)
- [Documentation Index](#documentation-index)
- [Contributing & Security](#contributing--security)
- [Sponsorship & Funding](#sponsorship--funding)
- [License](#license)

---

## Overview

Mythos Agent is a production-grade security vulnerability discovery and autonomous agent system inspired by frontier security research. It bridges high-order reasoning models with deterministic code analysis tools to identify, self-challenge, and validate critical software vulnerabilities.

### Key Capabilities

- **Autonomous Operator Swarm:** Reconnaissance, Scanner, Exploiter, Validator, and Analyst operators coordinated across a shared integrity ledger.
- **Universal LLM Layer:** Pluggable, keyless-compatible provider architecture supporting Anthropic, OpenRouter, Venice AI, xAI Grok, OpenAI, local Ollama/vLLM endpoints, and Mock mode.
- **Strict Scope Containment:** Hard egress filters with CIDR blocks, localhost guards, and authorized domain validation to prevent unintended reconnaissance or test execution.
- **Model Context Protocol (MCP):** Stdio MCP server exposing vulnerability tools (`mythos_scan_target`, `mythos_validate_finding`) to Claude Desktop and Cursor.
- **Dynamic Simulation & Verification:** Integrated AST parsing, sandbox executor, false-positive pruning, and dismissal memory tracking.

---

## Architecture & 8-Phase Discovery Scaffold

```
+---------------------------------------------------------------------------------+
|                                 SWARM COORDINATOR                               |
|   Recon Operator -> Scanner Operator -> Exploiter Operator -> Validator/Analyst  |
+---------------------------------------------------------------------------------+
                                         |
                                         v
 [Phase 1: Code Browsing & AST]  --> [Phase 2: File Ranking & Heuristics]
                                         |
                                         v
 [Phase 3: Threat Surface Mapping] -> [Phase 4: LIVE Agentic Vulnerability Hunt]
                                         |
                                         v
 [Phase 5: Adversarial Self-Challenge] -> [Phase 6: Skeptical Validator Agent]
                                         |
                                         v
 [Phase 7: Aggregation & De-dupe] -> [Phase 8: Dynamic Live-Exec / Sandbox]
```

1. **Phase 1: Code Browsing & Surface Mapping** — Builds lexical maps and identifies entry points.
2. **Phase 2: Heuristic File Ranking** — Prioritizes high-risk attack surfaces.
3. **Phase 3: Threat Surface Analysis** — Identifies auth boundaries, input ingestion, and crypto primitives.
4. **Phase 4: Agentic Hunting** — LLM-driven vulnerability scanning across OWASP Top 10 / CWE classifications.
5. **Phase 5: Adversarial Challenge** — Proactively challenges preliminary findings to weed out false positives.
6. **Phase 6: Skeptical Validator** — Re-verifies surviving issues with context-aware proof-of-concept tests.
7. **Phase 7: Aggregation & De-duplication** — Synthesizes unique fingerprints and dismisses known false positives.
8. **Phase 8: Execution-Based Verification** — Dynamic validation within isolated sandboxes.

---

## Multi-Operator Autonomous Swarm

The system provisions independent specialized operators:

| Operator | Role | Default Focus |
|---|---|---|
| **Recon** | Surface discovery & indexing | File extensions, routes, entrypoints |
| **Scanner** | Static & semantic vulnerability discovery | CWE-89, CWE-78, CWE-79, CWE-22, etc. |
| **Exploiter** | Proof-of-concept validation | Payloads and exploitability feasibility |
| **Validator** | Skeptical false-positive elimination | Context checking and mitigation verification |
| **Analyst** | Report generation & executive summary | Markdown/JSON audit reports with remediation steps |

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Academypeep/0707.git
cd 0707

# Install dependencies
npm ci
```

### Running an Autonomous Scan

Run the autonomous mission in mock mode without needing API keys:
```bash
npm run autonomous
```

Run with live providers:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
node index.js --autonomous --target ./lib --provider anthropic
```

---

## CLI Usage

### Available npm Scripts

| Command | Action |
|---|---|
| `npm test` | Run Jest unit and integration test suites |
| `npm run autonomous` | Execute full multi-operator swarm in mock mode |
| `npm run dev` | Launch agent scanner with $3.00 budget against local directory |
| `npm run verify-claims` | Validate benchmark claims against `benchmarks.json` |

### CLI Options

```
Options:
  --target <path|domain>    Target directory or authorized domain (default: ".")
  --budget <usd>            Maximum LLM cost budget (default: 5.00)
  --provider <name>         LLM provider (anthropic, openrouter, venice, xai, openai, local, mock)
  --model <id>              Model identifier (e.g. claude-3-7-sonnet, fable-5, etc.)
  --autonomous              Activate multi-operator swarm mode
  --allowMock               Enable mock provider mode for offline verification
  --mcp                     Start in stdio Model Context Protocol (MCP) mode
```

---

## Model Context Protocol (MCP) Server

Mythos Agent implements a stdio MCP server for direct integration into AI workspaces:

```bash
node index.js --mcp
```

Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mythos-agent": {
      "command": "node",
      "args": ["/path/to/0707/index.js", "--mcp"]
    }
  }
}
```

---

## Running Tests

All 150+ unit and integration tests run via Jest:

```bash
npm test
```

Test suites cover:
- Swarm coordination and multi-operator workflows
- Universal LLM provider integration & fallback
- Egress network containment and authorization gates
- Static vulnerability analysis and heuristics
- Report generation and Markdown formatting

---

## The Fable 5 Research Arc

This repository also contains research materials detailing the Claude Mythos Preview and Claude Fable 5 deployment and suspension timeline (June 2026):

- **Interactive Web Showcase:** Launch `index.html` or `mythos-deep-dive.html` in your browser.
- **Live Deployment:** [Claude Fable 5 Analysis Site](https://nraj-dataanalytics.github.io/Claude-Fable-5-Analysis/)
- **Data & Benchmarks:** `benchmarks.json` and `timeline.json`.
- **In-Depth Analysis:** See [`docs/analysis.md`](docs/analysis.md) and [`docs/fable5-data-analyst-guide.md`](docs/fable5-data-analyst-guide.md).

---

## Documentation Index

- [`QUICKSTART.md`](QUICKSTART.md) — Comprehensive guide to setup and provider selection.
- [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) — Technical deep-dive on agent mechanics.
- [`docs/analysis.md`](docs/analysis.md) — Research analysis on the Mythos and Fable 5 frontier arc.
- [`docs/fable5-data-analyst-guide.md`](docs/fable5-data-analyst-guide.md) — Practical guide for data and security analysts.
- [`CHANGELOG.md`](CHANGELOG.md) — Release notes and milestone tracking.

---

## Contributing & Security

We welcome contributions! Please review our community guidelines before submitting code:
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Support Options](SUPPORT.md)

---

## Sponsorship & Funding

Mythos Agent is an independent open-source research and engineering initiative. Ongoing sponsorship accelerates:
- Development of new multi-agent operators and tool bridges.
- Expansion of zero-day detection heuristics and AST analyzers.
- Maintenance of keyless LLM connectors and MCP server capabilities.

### Support the Project

- **[Sponsor on GitHub Sponsors](https://github.com/sponsors/Academypeep)**
- **[Back us on Open Collective](https://opencollective.com/mythos-agent)**
- **[Support via Ko-fi](https://ko-fi.com/academypeep)**

### Corporate Sponsorship Tiers

| Tier | Level | Benefits |
|---|---|---|
| **Community Backer** | $10 / month | Name / handle in Backers list |
| **Power Researcher** | $50 / month | Priority issue triage & prompt template previews |
| **Bronze Sponsor** | $250 / month | Company logo in README & documentation portal |
| **Gold Enterprise** | $1,000+ / month | Top README banner logo, monthly 45-min consultation & feature prioritization |

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
