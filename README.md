<h1 align="center">🛡️ ARGUS</h1>

<p align="center"><b>Autonomous Offensive-Security & Vulnerability-Research Platform</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/interface-CLI%20%2B%20Web%20Workspace-1F6FEB" alt="Interfaces">
  <img src="https://img.shields.io/badge/status-research%20%2F%20WIP-orange" alt="Status">
  <img src="https://img.shields.io/badge/use-authorized%20only-red" alt="Authorized use only">
</p>

---

> ### ⚠️ Authorized use only
> ARGUS is built for **authorized penetration testing, bug-bounty programs, and security research**. Only run it against systems you own or have **explicit written permission** to test. Scope and policy constraints are enforced throughout the platform, but the operator is always responsible for staying inside their authorization.

---

## What is ARGUS?

ARGUS is an **AI-assisted, scope-aware research platform** that helps security researchers move from raw reconnaissance to prioritized, evidence-backed findings. It coordinates recon tooling, builds a knowledge graph of what it learns, correlates observations into hypotheses, and keeps a queue of investigations ranked by priority — with an explainability trail behind every decision.

The design goal is to automate the slow, mechanical parts of a hunt **without ever letting a language model trigger a real-world action on its own**: every command an agent proposes passes through a deterministic authorization gate before it can run.

## Key capabilities

- **🔍 Reconnaissance orchestration** — coordinates recon specialists and tools, normalizing their output into structured observations.
- **🕸️ Knowledge-graph construction** — fuses evidence into a graph of hosts, services, technologies, and relationships.
- **🧠 Vector RAG & semantic search** — self-contained, offline embedding + SQLite-vec vector store for searching findings, evidence, and a CVE knowledge base.
- **🔗 Correlation & evidence fusion** — turns scattered observations into evidence-backed hypotheses.
- **📋 Investigation queues & priority scoring** — ranks what a researcher should look at next.
- **🤖 Agentic ReAct hunt loop** — an AI hunt engine that reasons, proposes commands, and acts step-by-step under human-in-the-loop approval.
- **🧾 Explainability** — every hypothesis and priority score carries a traceable rationale.
- **💬 Conversational memory** — persistent, multi-session memory of attack patterns, decisions, and corrections.
- **🖥️ Web workspace** — a FastAPI hunt console with live event streaming (SSE), inline approval cards, and a graph view.

## Safety model

ARGUS treats its own LLM as an **untrusted actor**:

- **Deterministic command-authorization gate** — a tool allowlist plus argument policy validates every proposed command; the model cannot widen its own scope.
- **Single-use nonces** — hunt actions are authorized once and cannot be replayed.
- **Hardened Docker sandbox** — commands execute inside an isolated, resource-constrained container.
- **Scope & policy enforcement** — targets outside the authorized scope are rejected at the boundary, not in the prompt.

## Architecture

```
argus/
├── recon/          # reconnaissance specialists & collectors
├── knowledge/      # knowledge graph + CVE knowledge base
├── vector/         # embeddings + SQLite-vec vector store (offline)
├── correlation/    # observation correlation & evidence fusion
├── hypothesis/     # evidence-backed hypothesis generation
├── investigation/  # investigation queues & priority scoring
├── agent/          # agentic ReAct hunt loop, tool catalog, Docker sandbox
├── authorization/  # deterministic command gate & scope policy
├── mission/        # mission-based runtime & orchestration
├── runtime/        # event bus, lifecycle, mission runtime
├── memory/         # persistent conversational memory
├── workspace/      # FastAPI web workspace + hunt console
├── explain/        # explainability / rationale trails
└── cli/            # Typer command-line interface
```

## Quickstart

```bash
# 1. Clone
git clone https://github.com/kumar-varun024/argus.git
cd argus

# 2. Create an environment (Python 3.11+)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install
pip install -e .

# 4. Configure LLM provider keys (see .env.example for the variables)
cp .env.example .env
# ...edit .env with your provider key(s)...

# 5. Explore the CLI
argus --help
```

## CLI overview

ARGUS ships a rich Typer CLI. A few of the command groups:

| Command | Purpose |
|---|---|
| `argus scan` | Run a reconnaissance / scanning pass against a target |
| `argus workspace` | Launch the web hunt console (FastAPI workspace) |
| `argus mission` | Manage mission-based runs |
| `argus agent` | Drive the agentic hunt loop |
| `argus auth` | Manage authorization scope & policy |
| `argus knowledge` | Query the knowledge graph & CVE base |
| `argus vector` | Semantic / vector search over findings & evidence |
| `argus research` | Research planning |
| `argus investigations` | Work the prioritized investigation queue |
| `argus explain` | Inspect the rationale behind a finding |

Run `argus <group> --help` for the full command set.

## Project status

ARGUS is an **active research / work-in-progress** project exploring safe autonomy for offensive-security workflows. Interfaces and internals may change.

## License

See [`LICENSE`](LICENSE).
