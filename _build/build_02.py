"""Builder for 02_Tanium_Decommission_Agent.ipynb
Cell convention: outer delimiter r'''...''' ; inner code uses only \"\"\" docstrings.
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from nbtools import md, code, build, validate_code_syntax

OUT = os.path.join(os.path.dirname(__file__), "..", "02_Tanium_Decommission_Agent.ipynb")
cells = []

cells.append(md(r'''
# Problem 2 — Tanium Decommission Agent

> *When a workstation is set to Retired or In Stock, ITE gets a task to remove the device
> from Tanium (other statuses might kick this off). This requires a user with Tanium
> access to log in, verify the device is offline, purge it from Tanium Data Services, and
> delete it from the asset database. Automate this process to reduce manual intervention.*

## Business context
Every retired endpoint left in Tanium inflates the license count, pollutes patch/compliance
reporting, and creates dead entries an analyst must hand-clean. The task is repetitive but
**not** zero-judgment: you must confirm the device is *really* gone before you purge it. A
"Retired" box that is still checking into Tanium is a red flag — it may have been reissued,
mis-statused, or (worst case) stolen and still phoning home.

## What this agent does
A **LangGraph** workflow triggered by a ServiceNow task (status → `Retired` / `In Stock` /
other configured triggers) that:

1. **Intake** — parse the SNOW task; resolve the CI in the **ServiceNow CMDB**.
2. **Verify** — query **Tanium** for the endpoint: how many matches, and last check-in.
3. **Assess** — an LLM reasoning step decides `PROCEED`, `HOLD`, or `ESCALATE`, handling the
   messy cases (still online, duplicate registrations, no CMDB record, no Tanium record).
4. **Decide** — code-enforced guardrails veto any purge of an online/ambiguous device.
5. **Approve** — pause for a human before the destructive purge/delete.
6. **Execute** — purge from Tanium Data Service → delete (decommission) the CMDB CI →
   close the SNOW task, auditing every step.

```
  ServiceNow task ─► intake ─► verify ─► assess ─► decide ─► [approval] ─► execute ─► report
   (Retired/InStock)  │         │         (LLM)    (guardrails)  ▲          │
                    CMDB      Tanium                              │      purge+delete
                    lookup   last-seen                       interrupt()   +close task
```

**Safety stance.** "Verify the device is offline" is the load-bearing control. It is a
hard guardrail in code (not a suggestion to the model): if Tanium shows a recent check-in,
the agent will **not** purge — it holds and routes to a human.
'''))

# ---- shared scaffolding (md + 3 code cells), same pattern as notebook 01 ----
cells.append(md(r'''
## 0. Setup — config, secrets, LLM, audit

Runs with **no credentials**: ServiceNow, the CMDB, and Tanium are all simulated. Set
`ANTHROPIC_API_KEY` (or Azure OpenAI vars) in `.env` to enable real LLM reasoning; without
it, a deterministic offline stub keeps the whole flow runnable.
'''))

cells.append(code(r'''
import os, json, datetime as dt
from typing import TypedDict, Literal
from pydantic import BaseModel, Field
import pandas as pd

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import interrupt, Command
from langchain_core.messages import SystemMessage, HumanMessage

try:
    from dotenv import load_dotenv; load_dotenv()
except Exception:
    pass
print("Imports OK")
'''))

cells.append(code(r'''
def get_secret(name, default=None):
    v = os.getenv(name)
    if v:
        return v
    try:
        with open("config.local.json") as f:
            return json.load(f).get(name, default)
    except FileNotFoundError:
        return default

AUDIT = []
def audit(action, target, detail=None, actor="tanium-agent"):
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "actor": actor, "action": action, "target": target, "detail": detail or {}}
    AUDIT.append(rec)
    print(f"  [audit] {action:24s} {target}  {detail or ''}")
    return rec
print("Secrets + audit ready")
'''))

cells.append(code(r'''
def build_llm(temperature=0, model=None):
    provider = os.getenv("LLM_PROVIDER", "anthropic").lower()
    model = model or os.getenv("LLM_MODEL")
    try:
        if provider == "anthropic":
            key = get_secret("ANTHROPIC_API_KEY")
            if not key:
                return None
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model or "claude-sonnet-4-6",
                                 temperature=temperature, api_key=key, max_tokens=2048)
        if provider == "azure_openai":
            key = get_secret("AZURE_OPENAI_API_KEY")
            if not key:
                return None
            from langchain_openai import AzureChatOpenAI
            return AzureChatOpenAI(
                azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1"),
                api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
                azure_endpoint=get_secret("AZURE_OPENAI_ENDPOINT"),
                api_key=key, temperature=temperature)
        if provider == "openai":
            key = get_secret("OPENAI_API_KEY")
            if not key:
                return None
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model=model or "gpt-4.1", api_key=key, temperature=temperature)
    except Exception as e:
        print("build_llm: offline stub ->", e)
        return None
    return None

LLM = build_llm()
LLM_AVAILABLE = LLM is not None
print("LLM:", "LIVE (" + os.getenv("LLM_PROVIDER", "anthropic") + ")" if LLM_AVAILABLE
      else "OFFLINE deterministic stub (set an API key in .env to enable real reasoning)")

def llm_structured(system, user, schema, demo):
    if LLM is None:
        return demo
    return LLM.with_structured_output(schema).invoke(
        [SystemMessage(content=system), HumanMessage(content=user)])
'''))

cells.append(md(r'''
## 1. Simulated ServiceNow, CMDB, and Tanium

The incoming task batch is crafted to cover the cases that make this *not* a trivial
script: a clean retire, a still-online device, a duplicate Tanium registration, and a
device already absent from Tanium. Each mock names the **real** REST call it replaces.
'''))

cells.append(code(r'''
# ---------------------------------------------------------------------------
# MOCK ServiceNow tasks — created when a CI's status changes to a trigger value.
# ---------------------------------------------------------------------------
INBOUND_TASKS = [
    {"number": "TASK0012", "hostname": "WS-FIN-204",   "status": "Retired"},
    {"number": "TASK0013", "hostname": "WS-ENG-118",   "status": "In Stock"},
    {"number": "TASK0014", "hostname": "WS-SALES-077", "status": "Retired"},
    {"number": "TASK0015", "hostname": "WS-HR-009",    "status": "Retired"},
    {"number": "TASK0016", "hostname": "WS-MFG-330",   "status": "Retired"},
]

def snow_fetch_decommission_tasks():
    """Open ITE decommission tasks (status change -> Retired/In Stock/...)."""
    return list(INBOUND_TASKS)
    # === REAL API ===
    # GET {SNOW}/api/now/table/sc_task?sysparm_query=stateIN1,2^short_descriptionLIKEdecommission

def snow_update(task, state, work_notes=""):
    audit("servicenow.update_task", task, {"state": state, "notes": work_notes[:60]})
    return {"number": task, "state": state}
    # === REAL API === PATCH {SNOW}/api/now/table/sc_task/{sys_id}

# ---------------------------------------------------------------------------
# MOCK CMDB (ServiceNow cmdb_ci_computer)
# ---------------------------------------------------------------------------
_CMDB = {
    "WS-FIN-204":   {"sys_id": "ci_fin204",  "serial": "5CD1FIN204", "last_user": "a.holt",  "status": "Retired"},
    "WS-ENG-118":   {"sys_id": "ci_eng118",  "serial": "5CD1ENG118", "last_user": "d.park",  "status": "In Stock"},
    "WS-SALES-077": {"sys_id": "ci_sal077",  "serial": "5CD1SAL077", "last_user": "r.diaz",  "status": "Retired"},
    "WS-HR-009":    {"sys_id": "ci_hr009",   "serial": "5CD1HR009",  "last_user": "t.young", "status": "Retired"},
    "WS-MFG-330":   {"sys_id": "ci_mfg330",  "serial": "5CD1MFG330", "last_user": "b.singh", "status": "Retired"},
}

def cmdb_lookup(hostname):
    ci = _CMDB.get(hostname)
    return dict(ci, hostname=hostname) if ci else None
    # === REAL API === GET {SNOW}/api/now/table/cmdb_ci_computer?sysparm_query=name={hostname}

def cmdb_decommission(sys_id):
    audit("cmdb.decommission_ci", sys_id, {"install_status": "Decommissioned"})
    return True
    # === REAL API === PATCH cmdb_ci_computer/{sys_id} {install_status:7}  (retire, don't hard-delete)
'''))

cells.append(code(r'''
# ---------------------------------------------------------------------------
# MOCK Tanium — find endpoint(s) + last check-in, and purge from Data Service.
# Scenarios keyed by hostname:
#   FIN-204 : single match, offline 45d        -> clean purge
#   ENG-118 : single match, seen 2h ago        -> STILL ONLINE (guardrail HOLD)
#   SALES-077: TWO matches (dup reg, 60d & 5d) -> ambiguous (ESCALATE)
#   HR-009  : no match (already gone)          -> nothing to purge, CMDB-only
#   MFG-330 : single match, offline 12d        -> clean purge
# ---------------------------------------------------------------------------
def _seen(hours_ago):
    return (dt.datetime(2026, 6, 2, 9, 0) - dt.timedelta(hours=hours_ago)).isoformat()

_TANIUM = {
    "WS-FIN-204":   [{"computer_id": "t-1001", "last_seen": _seen(45 * 24)}],
    "WS-ENG-118":   [{"computer_id": "t-1002", "last_seen": _seen(2)}],
    "WS-SALES-077": [{"computer_id": "t-1003", "last_seen": _seen(60 * 24)},
                     {"computer_id": "t-1817", "last_seen": _seen(5 * 24)}],
    "WS-HR-009":    [],
    "WS-MFG-330":   [{"computer_id": "t-1004", "last_seen": _seen(12 * 24)}],
}
NOW_TANIUM = dt.datetime(2026, 6, 2, 9, 0)

def tanium_find(hostname):
    """Return Tanium computer records matching this hostname (0, 1, or many)."""
    out = []
    for m in _TANIUM.get(hostname, []):
        last = dt.datetime.fromisoformat(m["last_seen"])
        out.append({**m, "days_since_seen": round((NOW_TANIUM - last).total_seconds() / 86400, 1)})
    return out
    # === REAL API === Tanium GraphQL: query { endpoints(filter:{name:$h}){ id eidLastSeen } }
    #   or REST: GET /api/v2/system_status  (filter client name)

def tanium_purge(computer_id):
    audit("tanium.purge_data_service", computer_id)
    return True
    # === REAL API === Tanium GraphQL mutation: endpointDelete(id:$id)  (removes from TDS)
    #   or the "Delete from Tanium" action via /api/v2/actions on the System Status group.
'''))

cells.append(md(r'''
## 2. Trigger policy + guardrails

`OFFLINE_MIN_DAYS` is the safety window: a device must have been silent in Tanium for at
least this long before a purge is permitted. Online or ambiguous devices are vetoed in
code regardless of what the model concludes.
'''))

cells.append(code(r'''
TRIGGER_STATUSES = {"Retired", "In Stock", "Disposed", "Lost/Stolen"}
OFFLINE_MIN_DAYS = 3.0     # Tanium must show no check-in for at least this long

def guardrail_block_purge(assessment):
    """Return a reason string if the destructive purge must be vetoed, else None."""
    matches = assessment["tanium_matches"]
    if len(matches) > 1:
        return f"ambiguous: {len(matches)} Tanium registrations for one hostname"
    if len(matches) == 1 and matches[0]["days_since_seen"] < OFFLINE_MIN_DAYS:
        return (f"device still checking in ({matches[0]['days_since_seen']}d ago "
                f"< {OFFLINE_MIN_DAYS}d) — NOT offline")
    return None
print("Triggers:", TRIGGER_STATUSES, "| offline window:", OFFLINE_MIN_DAYS, "days")
'''))

cells.append(md('## 3. Agent state + reasoning schema'))

cells.append(code(r'''
Decision = Literal["PROCEED", "HOLD", "ESCALATE"]

class EndpointDecision(BaseModel):
    task: str
    hostname: str
    decision: Decision
    purge_tanium: bool = Field(description="true only if a single, offline Tanium record exists")
    confidence: float = Field(ge=0, le=1)
    rationale: str

class AgentState(TypedDict):
    tasks: list[dict]
    assessed: list[dict]          # task + cmdb + tanium evidence + decision
    proposed: list[dict]          # PROCEED items eligible for execution
    approved: list[str]           # task numbers approved by a human
    report: dict
'''))

cells.append(code(r'''
def rule_decide(ev) -> EndpointDecision:
    """Deterministic offline decision — mirrors the guardrail logic exactly."""
    base = dict(task=ev["task"], hostname=ev["hostname"])
    if ev["cmdb"] is None:
        return EndpointDecision(**base, decision="ESCALATE", purge_tanium=False,
            confidence=0.9, rationale="no CMDB record — cannot verify identity/ownership")
    matches = ev["tanium_matches"]
    if len(matches) > 1:
        return EndpointDecision(**base, decision="ESCALATE", purge_tanium=False,
            confidence=0.85, rationale=f"{len(matches)} Tanium registrations — duplicate/reuse, needs a human")
    if len(matches) == 1 and matches[0]["days_since_seen"] < OFFLINE_MIN_DAYS:
        return EndpointDecision(**base, decision="HOLD", purge_tanium=False,
            confidence=0.95, rationale=f"still checking in {matches[0]['days_since_seen']}d ago — not offline")
    if len(matches) == 0:
        return EndpointDecision(**base, decision="PROCEED", purge_tanium=False,
            confidence=0.8, rationale="absent from Tanium already — only CMDB cleanup needed")
    return EndpointDecision(**base, decision="PROCEED", purge_tanium=True,
        confidence=0.9, rationale=f"single record, offline {matches[0]['days_since_seen']}d — safe to purge")
'''))

cells.append(md('## 4. Graph nodes'))

cells.append(code(r'''
def n_intake(state: AgentState) -> dict:
    tasks = [t for t in snow_fetch_decommission_tasks() if t["status"] in TRIGGER_STATUSES]
    audit("intake.tasks", "servicenow", {"count": len(tasks)})
    return {"tasks": tasks}

def n_verify(state: AgentState) -> dict:
    evidence = []
    for t in state["tasks"]:
        ci = cmdb_lookup(t["hostname"])
        matches = tanium_find(t["hostname"])
        evidence.append({"task": t["number"], "hostname": t["hostname"],
                         "status": t["status"], "cmdb": ci, "tanium_matches": matches})
        print(f"[verify] {t['hostname']:14s} status={t['status']:9s} "
              f"cmdb={'Y' if ci else 'N'} tanium_matches={len(matches)}")
    return {"assessed": evidence}
'''))

cells.append(code(r'''
ASSESS_SYS = (
    "You are a Tanium administrator deciding whether a retired endpoint can be safely "
    "purged. Output PROCEED, HOLD, or ESCALATE. A device may be purged ONLY if it has a "
    "single Tanium registration that has been offline for at least "
    f"{OFFLINE_MIN_DAYS} days. If it is still checking in -> HOLD. If there are multiple "
    "registrations or no CMDB record -> ESCALATE. Set purge_tanium true only when a single "
    "offline Tanium record exists (false when the device is already absent from Tanium)."
)

def n_assess(state: AgentState) -> dict:
    out = []
    for ev in state["assessed"]:
        user = json.dumps({k: ev[k] for k in ("task", "hostname", "status", "cmdb", "tanium_matches")},
                          indent=2, default=str)
        demo = rule_decide(ev)
        decision = llm_structured(ASSESS_SYS, "Decide for this endpoint:\n" + user,
                                  EndpointDecision, demo)
        d = decision.model_dump()
        d["sys_id"] = ev["cmdb"]["sys_id"] if ev["cmdb"] else None
        d["tanium_ids"] = [m["computer_id"] for m in ev["tanium_matches"]]
        d["_evidence"] = ev
        out.append(d)
        print(f"[assess] {ev['hostname']:14s} -> {d['decision']:8s} "
              f"(purge_tanium={d['purge_tanium']}) :: {d['rationale']}")
    return {"assessed": out}
'''))

cells.append(code(r'''
def n_decide(state: AgentState) -> dict:
    proposed = []
    for d in state["assessed"]:
        if d["decision"] != "PROCEED":
            snow_update(d["task"], "on_hold" if d["decision"] == "HOLD" else "escalated",
                        d["rationale"])
            continue
        block = guardrail_block_purge(d["_evidence"])   # defense in depth vs the LLM
        if block:
            audit("guardrail.block_purge", d["hostname"], {"reason": block})
            snow_update(d["task"], "on_hold", "guardrail: " + block)
            continue
        proposed.append(d)
    print(f"[decide] {len(proposed)} endpoint(s) cleared for execution")
    return {"proposed": proposed}

def n_approval(state: AgentState) -> dict:
    proposed = state["proposed"]
    if not proposed:
        return {"approved": []}
    decision = interrupt({
        "type": "approve_decommission",
        "summary": f"{len(proposed)} endpoint(s) to purge/decommission",
        "endpoints": [{"task": p["task"], "hostname": p["hostname"],
                       "purge_tanium": p["purge_tanium"], "rationale": p["rationale"]}
                      for p in proposed],
        "instructions": "resume with {'approved': [task numbers]} or {'approved': 'ALL'}",
    })
    approved = decision.get("approved", []) if isinstance(decision, dict) else []
    if approved == "ALL":
        approved = [p["task"] for p in proposed]
    audit("human.approval", "decommission-batch", {"approved": approved})
    return {"approved": approved}
'''))

cells.append(code(r'''
def n_execute(state: AgentState) -> dict:
    by_task = {p["task"]: p for p in state["proposed"]}
    purged, decommissioned = [], []
    for task in state["approved"]:
        p = by_task[task]
        if p["purge_tanium"]:
            for cid in p["tanium_ids"]:
                tanium_purge(cid)
            purged.append(p["hostname"])
        if p["sys_id"]:
            cmdb_decommission(p["sys_id"])
            decommissioned.append(p["hostname"])
        snow_update(task, "closed_complete", "Decommissioned by Tanium agent.")
    report = {
        "processed": len(state["assessed"]),
        "purged_from_tanium": purged,
        "cmdb_decommissioned": decommissioned,
        "held_or_escalated": [d["hostname"] for d in state["assessed"]
                              if d["decision"] != "PROCEED"],
    }
    print(f"[execute] purged {len(purged)} from Tanium, "
          f"decommissioned {len(decommissioned)} CIs")
    return {"report": report}
'''))

cells.append(md('## 5. Build & compile the graph'))

cells.append(code(r'''
g = StateGraph(AgentState)
for name, fn in [("intake", n_intake), ("verify", n_verify), ("assess", n_assess),
                 ("decide", n_decide), ("approval", n_approval), ("execute", n_execute)]:
    g.add_node(name, fn)
g.add_edge(START, "intake")
g.add_edge("intake", "verify")
g.add_edge("verify", "assess")
g.add_edge("assess", "decide")
g.add_edge("decide", "approval")
g.add_edge("approval", "execute")
g.add_edge("execute", END)
app = g.compile(checkpointer=MemorySaver())
print("Graph compiled:", list(app.get_graph().nodes))
'''))

cells.append(md('## 6. Run it'))

cells.append(code(r'''
AUDIT.clear()
config = {"configurable": {"thread_id": "tanium-run-2026-06-02"}}
init = {"tasks": [], "assessed": [], "proposed": [], "approved": [], "report": {}}
result = app.invoke(init, config)

print("\n=== PAUSED FOR APPROVAL ===")
intr = result["__interrupt__"][0].value
print(intr["summary"])
for e in intr["endpoints"]:
    print(f"  - {e['task']}  {e['hostname']:14s} purge_tanium={e['purge_tanium']}  ({e['rationale']})")
'''))

cells.append(code(r'''
final = app.invoke(Command(resume={"approved": "ALL"}), config)
print("\n=== FINAL REPORT ===")
print(json.dumps(final["report"], indent=2))
'''))

cells.append(md('## 7. Results + audit trail'))

cells.append(code(r'''
rows = [{"task": d["task"], "hostname": d["hostname"], "decision": d["decision"],
         "purge_tanium": d["purge_tanium"], "rationale": d["rationale"]}
        for d in final["assessed"]]
display(pd.DataFrame(rows))
print()
display(pd.DataFrame(AUDIT)[["action", "target", "detail"]])
'''))

cells.append(md(r'''
## 8. Productionizing

**Trigger** — best is event-driven: a ServiceNow **Business Rule / Flow** fires a webhook
when `install_status` enters a trigger value, kicking the graph for that one CI (instead of
the batch poll shown here). Keep the poll as a safety-net sweep.

**Wire the real systems** (replace each `# === REAL API ===`):
- *ServiceNow*: Table API for `sc_task` + `cmdb_ci_computer`. Prefer setting
  `install_status = Decommissioned` (a soft retire that preserves history) over a hard delete.
- *Tanium*: the GraphQL API (`endpoints` query + delete mutation) or REST System Status +
  Actions. The service account needs only the "Computer Groups: Delete" content permission.

**Why the guardrail matters** — the demo's `WS-ENG-118` is marked *In Stock* yet still
checks into Tanium 2h ago. A naive script would purge a live machine. The agent holds it
and routes to a human. `WS-SALES-077` has two Tanium registrations (a reuse/duplicate) →
escalated, never auto-purged.

**Hardening**
- Idempotent: re-running must be safe (purging an already-purged ID is a no-op).
- Persist the checkpointer (Postgres/SQLite) so an approval can resume later; surface the
  approval as a ServiceNow approval record or a Teams Adaptive Card.
- Add a **dependency check** (Tanium "last logged in user" / recent patch activity) and a
  **chassis-type** guard so servers never flow through a workstation-retirement path.
- Treat the audit log as the change-management artifact attached back to the SNOW task.
'''))

build(OUT, cells, "Problem 2 — Tanium Decommission Agent")
validate_code_syntax(OUT)
