"""Builder for 01_AVD_Idle_Machine_Agent.ipynb"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from nbtools import md, code, build, validate_code_syntax

OUT = os.path.join(os.path.dirname(__file__), "..", "01_AVD_Idle_Machine_Agent.ipynb")

cells = []

cells.append(md(r'''
# Problem 1 — AVD Idle-Machine Lifecycle Agent

> *When a user simply stops using their AVD machine, it continues to incur monthly
> costs. We need to automate the discovery of idle machines, the notification of users,
> and subsequent decommissioning of any unneeded machines.*

## Business context
Every running Azure Virtual Desktop (AVD) **personal** session host bills compute +
managed disk **24×7** whether or not anyone logs in. A handful of forgotten D4s_v5 hosts
quietly burns **$1,500–$3,000+/year each**. The waste is invisible because nobody is
*using* the thing that's costing money — there's no angry user to file a ticket.

## What this agent does
A **LangGraph** workflow that runs on a schedule and:

1. **Discovers** every session host and pulls usage telemetry (last logon, CPU, active
   sessions, monthly cost) from Azure Monitor / the AVD control plane.
2. **Classifies** each host with an LLM reasoning step — `ACTIVE`, `IDLE_REVIEW`, or
   `DORMANT` — against an explicit reclamation policy, with a rationale.
3. **Notifies** the owner (resolved via Entra ID) over Teams/email, opens a grace
   period, and files a ServiceNow change.
4. **Decides** what to reclaim, honoring grace periods, `do-not-reclaim` tags, and user
   replies.
5. **Pauses for human approval** before anything irreversible.
6. **Decommissions** approved hosts: snapshot → deallocate → delete → remove from host
   pool → close the ServiceNow change, logging every step.

```
                ┌───────────┐
   schedule ──► │ discover  │  Azure Monitor / AVD REST  (mocked)
                └─────┬─────┘
                      ▼
                ┌───────────┐
                │ classify  │  LLM reasoning + reclamation policy
                └─────┬─────┘
                      ▼
                ┌───────────┐
                │  notify   │  Entra owner → Teams/email + ServiceNow  (mocked)
                └─────┬─────┘
                      ▼
                ┌───────────┐
                │  decide   │  apply grace / tags / replies + guardrails
                └─────┬─────┘
                      ▼
             ╔═══════════════════╗
             ║  approval gate    ║  ◄── interrupt(): waits for a human
             ╚═════════┬═════════╝
                       ▼
                ┌───────────┐
                │decommission│  snapshot → deallocate → delete → SNOW  (mocked)
                └─────┬─────┘
                      ▼
                ┌───────────┐
                │  report   │  savings + audit trail
                └───────────┘
```

**Why a `StateGraph` and not a free-roaming chatbot?** Deleting VMs is irreversible. The
*orchestration* (order, guardrails, the approval gate) is deterministic code; the LLM is
used only where judgment helps (classifying ambiguous usage, writing a human
notification). An optional tool-using ReAct "ops copilot" is shown at the end for the
ad-hoc-question style.
'''))

cells.append(md(r'''
## 0. Setup — config, secrets, LLM, audit

Runs with **no credentials**: Azure/Entra/ServiceNow/Teams are all simulated, and the LLM
falls back to a deterministic offline stub. Set `ANTHROPIC_API_KEY` (or Azure OpenAI vars)
in `.env` to turn on real reasoning.
'''))

cells.append(code(r'''
# Std lib
import os, json, textwrap, datetime as dt
from typing import TypedDict, Literal

# Third-party
from pydantic import BaseModel, Field
import pandas as pd

# LangGraph / LangChain (stable API across LangGraph 0.3 -> 1.x)
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
# ---- Secrets: env first, then config.local.json (gitignored). Never hardcoded. ----
def get_secret(name, default=None):
    v = os.getenv(name)
    if v:
        return v
    try:
        with open("config.local.json") as f:
            return json.load(f).get(name, default)
    except FileNotFoundError:
        return default

# ---- Audit trail: every side-effecting action is recorded for change evidence. ----
AUDIT = []
def audit(action, target, detail=None, actor="avd-agent"):
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "actor": actor, "action": action, "target": target, "detail": detail or {}}
    AUDIT.append(rec)
    print(f"  [audit] {action:22s} {target}  {detail or ''}")
    return rec

print("Secrets + audit ready")
'''))

cells.append(code(r'''
# ---- Provider-swappable LLM. Returns None when no key -> deterministic offline path. ----
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
        if provider == "groq":
            key = get_secret("GROQ_API_KEY")
            if not key:
                return None
            from langchain_groq import ChatGroq
            return ChatGroq(model=model or "llama-3.3-70b-versatile",
                            api_key=key, temperature=temperature)
    except Exception as e:
        print("build_llm: offline stub ->", e)
        return None
    return None

LLM = build_llm()
LLM_AVAILABLE = LLM is not None
print("LLM:", "LIVE (" + os.getenv("LLM_PROVIDER", "anthropic") + ")" if LLM_AVAILABLE
      else "OFFLINE deterministic stub (set an API key in .env to enable real reasoning)")

def llm_structured(system, user, schema, demo):
    """Return a `schema` instance: real LLM if available, else the deterministic `demo`."""
    if LLM is None:
        return demo
    return LLM.with_structured_output(schema).invoke(
        [SystemMessage(content=system), HumanMessage(content=user)])

def llm_text(system, user, demo):
    if LLM is None:
        return demo
    return LLM.invoke([SystemMessage(content=system), HumanMessage(content=user)]).content
'''))

cells.append(md(r'''
## 1. Simulated Azure / Entra / ServiceNow backends

Each mock is paired with the **real** SDK/REST call it stands in for (commented
`# === REAL API ===`). Swapping to production is a per-function change — the graph above
doesn't move.
'''))

cells.append(code(r'''
# ---------------------------------------------------------------------------
# MOCK AVD FLEET — a small, deliberately messy estate of personal session hosts.
# `monthly_cost` = compute (24x7) + managed disk, in USD.
# ---------------------------------------------------------------------------
TODAY = dt.date(2026, 6, 2)
def _days_ago(n): return (TODAY - dt.timedelta(days=n)).isoformat()

_FLEET = [
    # name, vm_size, last_logon_days_ago, avg_cpu_pct_14d, active_sessions, monthly_cost, owner_upn, tags
    ("avd-sales-01",  "Standard_D4s_v5", 2,   23.0, 1, 162.0, "j.rivera@contoso.com",  {}),
    ("avd-sales-02",  "Standard_D4s_v5", 41,  1.2,  0, 162.0, "m.chen@contoso.com",    {}),
    ("avd-eng-07",    "Standard_D8s_v5", 5,   58.0, 1, 312.0, "p.okafor@contoso.com",  {}),
    ("avd-eng-09",    "Standard_D8s_v5", 88,  0.4,  0, 312.0, "s.kapoor@contoso.com",  {}),
    ("avd-fin-03",    "Standard_D4s_v5", 33,  2.1,  0, 162.0, "l.nguyen@contoso.com",  {}),
    ("avd-exec-01",   "Standard_D8s_v5", 120, 0.2,  0, 312.0, "ceo@contoso.com",       {"do-not-reclaim": "exec-standby"}),
    ("avd-temp-12",   "Standard_D2s_v5", 67,  0.0,  0, 96.0,  "contractor-x@contoso.com", {"project": "ended-2026Q1"}),
    ("avd-ops-04",    "Standard_D4s_v5", 9,   31.0, 0, 162.0, "ops-team@contoso.com",  {}),
    ("avd-mktg-05",   "Standard_D4s_v5", 95,  0.1,  0, 162.0, "k.flores@contoso.com",  {}),
]

def azure_list_session_hosts():
    """Return all AVD session hosts with usage telemetry."""
    hosts = []
    for (name, size, lld, cpu, sess, cost, owner, tags) in _FLEET:
        hosts.append({
            "name": name, "vm_size": size, "last_logon": _days_ago(lld),
            "days_since_logon": lld, "avg_cpu_14d": cpu, "active_sessions": sess,
            "monthly_cost_usd": cost, "owner_upn": owner, "tags": tags,
            "power_state": "running",
        })
    return hosts
    # === REAL API ===
    # from azure.identity import DefaultAzureCredential
    # from azure.mgmt.desktopvirtualization import DesktopVirtualizationMgmtClient
    # from azure.monitor.query import LogsQueryClient
    # cred = DefaultAzureCredential()
    # avd = DesktopVirtualizationMgmtClient(cred, get_secret("AZURE_SUBSCRIPTION_ID"))
    # hosts = avd.session_hosts.list(resource_group, host_pool_name)
    # # last logon + CPU come from Log Analytics (WVDConnections, Perf) via LogsQueryClient
    # # monthly_cost from Cost Management Query API or a size->price table

def azure_snapshot_disk(host):
    audit("azure.snapshot_disk", host, {"snapshot": host + "-snap"}); return True
    # === REAL API === ComputeManagementClient.snapshots.begin_create_or_update(...)

def azure_deallocate_vm(host):
    audit("azure.deallocate_vm", host); return True
    # === REAL API === ComputeManagementClient.virtual_machines.begin_deallocate(rg, host)

def azure_delete_vm(host):
    audit("azure.delete_vm", host, {"also": ["os_disk", "nic"]}); return True
    # === REAL API === begin_delete VM, then disks + NIC; remove from host pool:
    # avd.session_hosts.delete(rg, host_pool, host)

print("Azure mock ready —", len(azure_list_session_hosts()), "session hosts")
'''))

cells.append(code(r'''
# ---------------------------------------------------------------------------
# MOCK Entra ID (owner lookup) + ServiceNow (change tickets) + Teams (notify)
# ---------------------------------------------------------------------------
def entra_get_owner(upn):
    """Resolve a UPN to a display name + manager (for escalation)."""
    name = upn.split("@")[0].replace(".", " ").replace("-", " ").title()
    return {"upn": upn, "display_name": name, "enabled": "contractor" not in upn,
            "manager_upn": "manager@contoso.com"}
    # === REAL API === Microsoft Graph: GET /users/{upn}?$select=displayName,accountEnabled
    #                  GET /users/{upn}/manager

def teams_notify(upn, subject, body):
    audit("teams.notify", upn, {"subject": subject})
    print(textwrap.indent(f"To: {upn}\nSubj: {subject}\n{body}", "      | "))
    return {"sent": True}
    # === REAL API === Graph: POST /chats/{id}/messages  OR  send an Outlook mail:
    #                  POST /users/{sender}/sendMail

_SNOW_SEQ = {"n": 1000}
def snow_create_change(short_desc, host, payload):
    _SNOW_SEQ["n"] += 1
    cid = f"CHG00{_SNOW_SEQ['n']}"
    audit("servicenow.create_change", host, {"change": cid, "desc": short_desc})
    return {"number": cid, "state": "assess"}
    # === REAL API === POST {SNOW}/api/now/table/change_request

def snow_update(change_number, state, work_notes=""):
    audit("servicenow.update", change_number, {"state": state})
    return {"number": change_number, "state": state}
    # === REAL API === PATCH {SNOW}/api/now/table/change_request/{sys_id}

print("Entra + ServiceNow + Teams mocks ready")
'''))

cells.append(md(r'''
## 2. Reclamation policy + guardrails

The policy is **explicit and code-enforced** so behavior is auditable and independent of
the model. The LLM classifies; these rules constrain what the agent is *allowed* to do.
'''))

cells.append(code(r'''
# Tunable policy
IDLE_REVIEW_DAYS = 30      # no logon this long -> review/notify
DORMANT_DAYS     = 60      # no logon this long + ~zero CPU -> reclaim candidate
DORMANT_CPU_MAX  = 5.0     # avg CPU% ceiling to be considered dormant
GRACE_DAYS       = 7       # notice period before delete is permitted
MAX_DELETIONS_PER_RUN = 3  # blast-radius cap

def guardrail_block_delete(host):
    """Return a reason string if this host must NOT be deleted, else None."""
    if host["tags"].get("do-not-reclaim"):
        return "tagged do-not-reclaim=" + host["tags"]["do-not-reclaim"]
    if host["active_sessions"] > 0:
        return "has an active session right now"
    if host["days_since_logon"] < DORMANT_DAYS:
        return f"last logon {host['days_since_logon']}d ago (< {DORMANT_DAYS}d dormant threshold)"
    return None

print("Policy loaded:",
      dict(IDLE_REVIEW_DAYS=IDLE_REVIEW_DAYS, DORMANT_DAYS=DORMANT_DAYS,
           GRACE_DAYS=GRACE_DAYS, MAX_DELETIONS_PER_RUN=MAX_DELETIONS_PER_RUN))
'''))

cells.append(md(r'''
## 3. Agent state + reasoning schema

`with_structured_output(HostClassification)` forces the LLM to return typed, validated
fields — no brittle string parsing. The same schema instance is produced by the offline
deterministic fallback, so downstream code is identical either way.
'''))

cells.append(code(r'''
Status = Literal["ACTIVE", "IDLE_REVIEW", "DORMANT"]
Action = Literal["KEEP", "DEALLOCATE", "NOTIFY", "DELETE"]

class HostClassification(BaseModel):
    name: str = Field(description="session host name")
    status: Status
    recommended_action: Action
    confidence: float = Field(ge=0, le=1)
    rationale: str = Field(description="one sentence, cites the telemetry")

class ClassificationBatch(BaseModel):
    items: list[HostClassification]

class AgentState(TypedDict):
    hosts: list[dict]
    classifications: list[dict]
    notified: list[dict]
    proposed_decommission: list[dict]   # [{name, action, monthly_cost, change}]
    approved_hosts: list[str]
    report: dict
'''))

cells.append(code(r'''
# Deterministic fallback classifier (used when no LLM key is set) — mirrors the policy.
def policy_classify(host) -> HostClassification:
    d, cpu, sess = host["days_since_logon"], host["avg_cpu_14d"], host["active_sessions"]
    if host["tags"].get("do-not-reclaim"):
        return HostClassification(name=host["name"], status="ACTIVE",
            recommended_action="KEEP", confidence=0.99,
            rationale="protected by do-not-reclaim tag")
    if d >= DORMANT_DAYS and cpu <= DORMANT_CPU_MAX and sess == 0:
        return HostClassification(name=host["name"], status="DORMANT",
            recommended_action="DELETE", confidence=0.9,
            rationale=f"no logon {d}d, avg CPU {cpu}%, 0 sessions -> reclaim")
    if d >= IDLE_REVIEW_DAYS and sess == 0:
        return HostClassification(name=host["name"], status="IDLE_REVIEW",
            recommended_action="NOTIFY", confidence=0.8,
            rationale=f"no logon {d}d -> notify owner, deallocate to stop compute spend")
    return HostClassification(name=host["name"], status="ACTIVE",
        recommended_action="KEEP", confidence=0.85,
        rationale=f"recent activity (logon {d}d ago, CPU {cpu}%)")
'''))

cells.append(md("## 4. Graph nodes"))

cells.append(code(r'''
def n_discover(state: AgentState) -> dict:
    print("[discover] querying AVD fleet + telemetry ...")
    hosts = azure_list_session_hosts()
    audit("discover.fleet", "host-pool", {"count": len(hosts)})
    return {"hosts": hosts}
'''))

cells.append(code(r'''
CLASSIFY_SYS = (
    "You are an Azure FinOps + AVD operations analyst. Classify each session host as "
    "ACTIVE, IDLE_REVIEW, or DORMANT and recommend KEEP, DEALLOCATE, NOTIFY, or DELETE. "
    f"Policy: IDLE_REVIEW>={IDLE_REVIEW_DAYS}d no logon; DORMANT>={DORMANT_DAYS}d no logon "
    f"AND avg CPU<={DORMANT_CPU_MAX}% AND 0 sessions. Never recommend DELETE for a host "
    "tagged do-not-reclaim or with an active session. Cite the telemetry in each rationale."
)

def n_classify(state: AgentState) -> dict:
    hosts = state["hosts"]
    user = "Classify these hosts:\n" + json.dumps(
        [{k: h[k] for k in ("name","days_since_logon","avg_cpu_14d",
                            "active_sessions","monthly_cost_usd","tags")} for h in hosts],
        indent=2)
    demo = ClassificationBatch(items=[policy_classify(h) for h in hosts])
    batch = llm_structured(CLASSIFY_SYS, user, ClassificationBatch, demo)
    cls = [c.model_dump() for c in batch.items]
    print(f"[classify] {sum(c['status']=='DORMANT' for c in cls)} dormant, "
          f"{sum(c['status']=='IDLE_REVIEW' for c in cls)} idle-review, "
          f"{sum(c['status']=='ACTIVE' for c in cls)} active")
    return {"classifications": cls}
'''))

cells.append(code(r'''
NOTIFY_SYS = ("You write short, friendly internal IT notices. 80 words max, no markdown "
              "headers. Tell the user their AVD host looks idle, give the reclaim date, "
              "and how to keep it (reply KEEP).")

def n_notify(state: AgentState) -> dict:
    by_name = {h["name"]: h for h in state["hosts"]}
    notified = []
    reclaim_date = (TODAY + dt.timedelta(days=GRACE_DAYS)).isoformat()
    for c in state["classifications"]:
        if c["status"] not in ("IDLE_REVIEW", "DORMANT"):
            continue
        host = by_name[c["name"]]
        owner = entra_get_owner(host["owner_upn"])
        # Idle hosts: stop paying for compute immediately while we wait (disk still bills).
        if host["active_sessions"] == 0 and host["power_state"] == "running":
            azure_deallocate_vm(host["name"])
        body = llm_text(NOTIFY_SYS,
            f"User {owner['display_name']}; host {host['name']}; "
            f"{host['days_since_logon']} days since logon; reclaim on {reclaim_date}.",
            demo=(f"Hi {owner['display_name']}, your AVD machine {host['name']} hasn't "
                  f"been used in {host['days_since_logon']} days, so we've paused it to "
                  f"stop charges. It will be removed on {reclaim_date} unless you reply "
                  f"KEEP to retain it. Thanks, IT Ops."))
        teams_notify(host["owner_upn"], "Action needed: idle AVD machine", body)
        chg = snow_create_change("Reclaim idle AVD host " + host["name"], host["name"],
                                 {"reclaim_date": reclaim_date})
        notified.append({"name": host["name"], "owner": host["owner_upn"],
                         "change": chg["number"], "reclaim_date": reclaim_date})
    print(f"[notify] notified {len(notified)} owner(s); idle hosts deallocated")
    return {"notified": notified}
'''))

cells.append(code(r'''
# Simulated user replies during the grace window (deterministic for a reproducible demo).
# In production this comes from a mailbox/Teams webhook or a self-service "Keep" button.
SIMULATED_REPLIES = {"s.kapoor@contoso.com": "KEEP"}   # avd-eng-09's owner: still need it

def n_decide(state: AgentState) -> dict:
    by_name = {h["name"]: h for h in state["hosts"]}
    notified_owner = {n["name"]: n for n in state["notified"]}
    proposed = []
    for c in state["classifications"]:
        if c["recommended_action"] != "DELETE":
            continue
        host = by_name[c["name"]]
        block = guardrail_block_delete(host)
        if block:
            audit("guardrail.block_delete", host["name"], {"reason": block})
            continue
        if SIMULATED_REPLIES.get(host["owner_upn"]) == "KEEP":
            audit("user.replied_keep", host["name"], {"owner": host["owner_upn"]})
            continue
        proposed.append({"name": host["name"], "action": "DELETE",
                         "monthly_cost": host["monthly_cost_usd"],
                         "change": notified_owner.get(host["name"], {}).get("change")})
    proposed = proposed[:MAX_DELETIONS_PER_RUN]   # blast-radius cap
    print(f"[decide] {len(proposed)} host(s) proposed for decommission "
          f"(after guardrails, replies, cap)")
    return {"proposed_decommission": proposed}
'''))

cells.append(code(r'''
def n_approval(state: AgentState) -> dict:
    proposed = state["proposed_decommission"]
    if not proposed:
        return {"approved_hosts": []}
    savings = sum(p["monthly_cost"] for p in proposed)
    # Pause the graph and hand control to a human. Resume with Command(resume=...).
    decision = interrupt({
        "type": "approve_decommission",
        "summary": f"{len(proposed)} hosts, ${savings:,.0f}/mo (${savings*12:,.0f}/yr) savings",
        "hosts": proposed,
        "instructions": "resume with {'approved': [host names]} or {'approved': 'ALL'}",
    })
    approved = decision.get("approved", []) if isinstance(decision, dict) else []
    if approved == "ALL":
        approved = [p["name"] for p in proposed]
    audit("human.approval", "decommission-batch", {"approved": approved})
    return {"approved_hosts": approved}
'''))

cells.append(code(r'''
def n_decommission(state: AgentState) -> dict:
    by_name = {h["name"]: h for h in state["hosts"]}
    proposed = {p["name"]: p for p in state["proposed_decommission"]}
    done, saved = [], 0.0
    for name in state["approved_hosts"]:
        host, p = by_name[name], proposed.get(name, {})
        azure_snapshot_disk(name)          # safety net before deletion
        azure_deallocate_vm(name)
        azure_delete_vm(name)
        if p.get("change"):
            snow_update(p["change"], "closed_complete",
                        "Host reclaimed by AVD agent; snapshot retained 30d.")
        done.append(name); saved += host["monthly_cost_usd"]
    report = {"decommissioned": done, "count": len(done),
              "monthly_savings_usd": round(saved, 2),
              "annual_savings_usd": round(saved * 12, 2)}
    print(f"[decommission] removed {len(done)} host(s); "
          f"${report['monthly_savings_usd']:,.0f}/mo saved")
    return {"report": report}
'''))

cells.append(md("## 5. Build & compile the graph"))

cells.append(code(r'''
g = StateGraph(AgentState)
g.add_node("discover", n_discover)
g.add_node("classify", n_classify)
g.add_node("notify", n_notify)
g.add_node("decide", n_decide)
g.add_node("approval", n_approval)
g.add_node("decommission", n_decommission)

g.add_edge(START, "discover")
g.add_edge("discover", "classify")
g.add_edge("classify", "notify")
g.add_edge("notify", "decide")
g.add_edge("decide", "approval")
g.add_edge("approval", "decommission")
g.add_edge("decommission", END)

# A checkpointer is REQUIRED for interrupt()/resume to work.
app = g.compile(checkpointer=MemorySaver())
print("Graph compiled:", list(app.get_graph().nodes))
'''))

cells.append(md(r'''
## 6. Run it

The run streams through `discover → classify → notify → decide` and then **pauses** at the
approval gate. We inspect the proposal, then resume with an approval decision.
'''))

cells.append(code(r'''
AUDIT.clear()
config = {"configurable": {"thread_id": "avd-run-2026-06-02"}}
result = app.invoke({"hosts": [], "classifications": [], "notified": [],
                     "proposed_decommission": [], "approved_hosts": [], "report": {}},
                    config)

print("\n=== PAUSED FOR APPROVAL ===")
intr = result["__interrupt__"][0].value
print(intr["summary"])
for h in intr["hosts"]:
    print(f"  - {h['name']:14s} ${h['monthly_cost']:.0f}/mo   change={h['change']}")
'''))

cells.append(code(r'''
# A human approves (here: approve ALL proposed). In production this is a Teams Adaptive
# Card / ServiceNow approval webhook that resumes the same thread_id.
final = app.invoke(Command(resume={"approved": "ALL"}), config)
print("\n=== FINAL REPORT ===")
print(json.dumps(final["report"], indent=2))
'''))

cells.append(md("## 7. Results — savings + audit trail"))

cells.append(code(r'''
rows = []
by_name = {h["name"]: h for h in final["hosts"]}
for c in final["classifications"]:
    h = by_name[c["name"]]
    rows.append({"host": c["name"], "status": c["status"], "action": c["recommended_action"],
                 "$/mo": h["monthly_cost_usd"], "days_idle": h["days_since_logon"],
                 "rationale": c["rationale"]})
df = pd.DataFrame(rows).sort_values("status")
display(df)

r = final["report"]
print(f"\nDecommissioned {r['count']} host(s): {', '.join(r['decommissioned']) or '-'}")
print(f"Savings: ${r['monthly_savings_usd']:,.0f}/mo  =>  ${r['annual_savings_usd']:,.0f}/yr")
'''))

cells.append(code(r'''
print("AUDIT TRAIL (", len(AUDIT), "events )")
display(pd.DataFrame(AUDIT)[["ts", "action", "target", "detail"]])
'''))

cells.append(md(r'''
## 8. Optional — ad-hoc "AVD ops copilot" (tool-using ReAct agent)

The graph above is the *unattended* pipeline. For interactive questions
("which idle hosts cost the most?"), a tool-calling agent is a better fit. This
demonstrates the second agentic pattern and **requires a live LLM key** (a ReAct loop
needs a real tool-calling model — there's no deterministic stub for free-form tool use).
'''))

cells.append(code(r'''
from langchain_core.tools import tool

@tool
def list_hosts() -> list:
    """List all AVD session hosts with cost + idle telemetry."""
    return azure_list_session_hosts()

@tool
def estimate_savings(host_names: list[str]) -> dict:
    """Estimate monthly/annual savings if the named hosts were decommissioned."""
    cost = {h["name"]: h["monthly_cost_usd"] for h in azure_list_session_hosts()}
    m = sum(cost.get(n, 0) for n in host_names)
    return {"monthly_usd": m, "annual_usd": m * 12, "hosts": host_names}

if LLM_AVAILABLE:
    from langgraph.prebuilt import create_react_agent
    copilot = create_react_agent(LLM, tools=[list_hosts, estimate_savings])
    q = ("Which hosts have been idle 30+ days with near-zero CPU, and what's the annual "
         "savings if we reclaim them? Be specific.")
    out = copilot.invoke({"messages": [HumanMessage(content=q)]})
    print(out["messages"][-1].content)
else:
    print("Skipped: set an LLM key in .env to run the ReAct copilot.")
'''))

cells.append(md(r'''
## 9. Productionizing

**Wire the real systems** — replace each `# === REAL API ===` block:
- *Discovery*: `azure-mgmt-desktopvirtualization` for the host pool; `azure-monitor-query`
  against `WVDConnections` (last logon) + `Perf` (CPU); Cost Management for `$/mo`.
- *Notify*: Microsoft Graph `sendMail` / Teams message; resolve owner + manager via Graph.
- *Decommission*: `azure-mgmt-compute` (snapshot → deallocate → delete VM/disk/NIC) +
  remove the session host from the pool.
- *Tickets/approval*: ServiceNow Change API; surface the approval gate as a Teams Adaptive
  Card or SNOW approval that resumes the graph thread.

**Operational hardening**
- Run unattended on a schedule (Azure Functions timer / Container Apps Job / cron) and
  persist the LangGraph checkpointer to **Postgres/SQLite** so an approval can resume days
  later.
- Identity: a least-privilege **service principal** scoped to the AVD resource group
  (Desktop Virtualization Contributor + Virtual Machine Contributor), not standing user
  creds.
- Prefer **DEALLOCATE before DELETE** + a retained snapshot — most savings come from
  stopping compute; deletion is the irreversible last step.
- Make every action **idempotent** and safe to re-run; treat the audit log as
  change-management evidence.

**Tuning** — start conservative (long grace, `MAX_DELETIONS_PER_RUN` low), watch
"reclaimed then re-requested" rate, then relax. Add seasonality awareness (don't reclaim
during a user's PTO from the HR calendar).
'''))

build(OUT, cells, "Problem 1 — AVD Idle-Machine Lifecycle Agent")
validate_code_syntax(OUT)
