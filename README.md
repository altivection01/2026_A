# 2026_A — Agentic AI Initiatives

Four self-contained Jupyter notebooks, each an **agentic** prototype for one of the
selected onsite problems. Every notebook runs **end-to-end out of the box** against
realistic *simulated* backends (Azure, Tanium, NVD, firewalls, ServiceNow, Entra ID),
with the real integration points clearly marked (`# === REAL API ===`) so a team can
swap a mock for a live call without restructuring anything.

| # | Notebook | Problem |
|---|----------|---------|
| 1 | [`01_AVD_Idle_Machine_Agent.ipynb`](01_AVD_Idle_Machine_Agent.ipynb) | Discover idle Azure Virtual Desktop hosts, notify owners, and decommission unneeded machines to stop wasted spend. |
| 2 | [`02_Tanium_Decommission_Agent.ipynb`](02_Tanium_Decommission_Agent.ipynb) | When a workstation goes **Retired / In Stock**, verify it's offline, purge it from Tanium, and delete it from the asset DB. |
| 3 | [`03_CVE_Prioritization_RAG_GraphRAG_Agent.ipynb`](03_CVE_Prioritization_RAG_GraphRAG_Agent.ipynb) | Give the agent a CVE (or a list); it prioritizes by real-world risk and returns grounded remediations. Adapts the RAG + GraphRAG methods from `JH_AI_P4/FullCode_Notebook.ipynb`. |
| 4 | [`04_Site_AllowDeny_Orchestration_Agent.ipynb`](04_Site_AllowDeny_Orchestration_Agent.ipynb) | Fulfill a GIS allow/deny-list request end-to-end across DNS, NGFW, Cloud Proxy/SWG, and Endpoint/EDR. |

## Design philosophy (shared across all four)

These are **operations** problems where an agent takes real, sometimes destructive,
action. The notebooks therefore follow a consistent, production-minded pattern rather
than a free-roaming chatbot:

- **LangGraph `StateGraph` orchestration.** Control flow (what runs when, fan-out,
  retries, guardrails) is deterministic graph code. The LLM is used at specific
  *reasoning* nodes (classify, validate, draft, synthesize) — the part that actually
  needs judgment — not to decide whether to delete a VM.
- **Human-in-the-loop approval gates.** Every irreversible action (delete VM, purge
  from Tanium, blacklist a domain) pauses the graph with a LangGraph `interrupt()` and
  resumes only on explicit approval.
- **Guardrails first.** Hard preconditions (device must be offline before purge; never
  block `microsoft.com`; never auto-allow a known-malicious indicator) are enforced in
  code, independent of the model.
- **Audit trail.** Every tool call and decision is logged for change-management evidence.
- **Mocks + real stubs.** All external systems are simulated so the notebooks run with
  zero infrastructure. Real SDK/REST calls sit right next to each mock, commented, ready
  to enable.
- **Provider-swappable LLM.** `build_llm()` defaults to Claude but switches to Azure
  OpenAI / OpenAI / Groq via one env var. If **no** LLM key is set, a deterministic
  offline stub keeps the whole flow runnable for demos.

Notebook 3 (CVE) additionally implements a full retrieval stack — dense RAG, a
knowledge-graph (GraphRAG) layer, hybrid retrieval, and a quantitative prioritization
engine (CVSS + EPSS + CISA KEV + asset exposure, SSVC-style) — and documents, section by
section, where the CVE domain calls for **enhancements** over the energy-report approach.

## Setup

> **Heads-up on environments.** LangGraph 1.x requires `langchain-core ≥ 1.0`, but the
> `JH_AI_P4` RAG notebook pins the `langchain 0.3.x` line. To avoid breaking that env,
> install these notebooks in a **fresh virtual environment**. (The agent code uses only
> the stable API shared by LangGraph 0.3 → 1.x, so the pinned 0.6 line in
> `requirements.txt` and the latest 1.x line both work.)

```bash
cd 2026_A
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # optional — notebooks run without it
# put ANTHROPIC_API_KEY (or Azure OpenAI vars) in .env to enable real reasoning

jupyter lab                   # or: code . / jupyter notebook
```

Running a notebook with **no `.env`** still works — infra is mocked and the LLM falls
back to a deterministic stub. Set one LLM key to see real agent reasoning.

## Security notes

- **No secrets are committed.** Keys load from environment / `.env` (gitignored) via
  `get_secret()`. There are no hardcoded credentials in any notebook.
- ⚠️ The sibling `JH_AI_P4/config.json` contains **live API keys in plaintext**
  (Anthropic, OpenAI, Groq, Cerebras, Neo4j). Consider rotating them and moving to env
  vars / a secrets manager; they should not live in a repo file.
- The destructive actions (decommission, purge, blacklist) are **gated behind explicit
  approval** and were designed to be run by an automation service principal with
  least-privilege, scoped roles — not a human's standing credentials.

## Repo layout

```
2026_A/
├── 01_AVD_Idle_Machine_Agent.ipynb
├── 02_Tanium_Decommission_Agent.ipynb
├── 03_CVE_Prioritization_RAG_GraphRAG_Agent.ipynb
├── 04_Site_AllowDeny_Orchestration_Agent.ipynb
├── requirements.txt
├── .env.example
└── README.md
```
