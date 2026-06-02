"""Builder for 04_Site_AllowDeny_Orchestration_Agent.ipynb
Cell convention: outer delimiter r'''...''' ; inner code uses only \"\"\" docstrings.
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from nbtools import md, code, build, validate_code_syntax

OUT = os.path.join(os.path.dirname(__file__), "..", "04_Site_AllowDeny_Orchestration_Agent.ipynb")
cells = []

cells.append(md(r'''
# Problem 4 — Site Allow/Deny-List Orchestration Agent

> *GIS requests a site to be whitelisted or blacklisted. Automate the open-to-end
> fulfillment of this operation. This may include whitelisting or blacklisting at the DNS
> layer, network/NGFW, use of a Cloud Proxy/SWG, or Endpoint agent.*

## Business context
A block/allow request sounds trivial but is actually a **fan-out, multi-system change**
that today bounces between teams: DNS, firewall, the web proxy, and endpoint. Done by
hand it's slow, inconsistent (blocked on the proxy but not DNS), and risky — an
allow-list entry quietly *weakens* security, and a careless block of `microsoft.com`
takes down the company.

## What this agent does
A **LangGraph** workflow that fulfills a request end-to-end across **all four enforcement
layers** and refuses to do the dangerous thing:

1. **Intake** — read the ServiceNow request (indicator, allow/deny, scope, justification).
2. **Triage** — classify the indicator (domain / URL / IP), pull threat-intel reputation,
   check for conflicts, and apply hard guardrails.
3. **Plan** — an LLM selects *which layers apply* for this indicator type + action and
   drafts a per-layer change plan with a rationale.
4. **Approve** — pause for a human (always for allow-listing; always when reputation is bad).
5. **Apply** — fan out to DNS, NGFW, SWG, and EDR adapters; **roll back** on partial failure.
6. **Verify** — confirm each layer actually enforces the change.
7. **Close** — update ServiceNow, notify the requester, audit everything.

```
                                        ┌─► DNS  (Umbrella / Infoblox RPZ)
  SNOW request ─► triage ─► plan ─► [approve] ─► apply ─┼─► NGFW (Palo Alto EDL)
   (allow/deny)   (guard-   (LLM    interrupt() (fan-out ├─► SWG  (Zscaler URL cat)
                   rails)   layers)             +rollback)└─► EDR  (Defender / CrowdStrike)
                                                              │
                                                          verify ─► close + notify
```

**Guardrails that override the model**
- **Never block critical infrastructure** (`microsoft.com`, Windows Update, your own
  domains, identity providers) — a deny request on these is refused and escalated.
- **Never auto-allow a known-malicious indicator** — it escalates for senior approval.
- Allow-list changes are time-boxed and always require human approval.
'''))

cells.append(md(r'''
## 0. Setup — config, secrets, LLM, audit
Runs with **no credentials** — ServiceNow, threat-intel, and all four enforcement layers
are simulated. Set an LLM key in `.env` for real planning; otherwise a deterministic stub
runs the same flow.
'''))

cells.append(code(r'''
import os, re, json, datetime as dt
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
def audit(action, target, detail=None, actor="gis-allowdeny-agent"):
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "actor": actor, "action": action, "target": target, "detail": detail or {}}
    AUDIT.append(rec)
    print(f"  [audit] {action:22s} {target}  {detail or ''}")
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
## 1. Simulated ServiceNow intake, threat-intel, and the four enforcement layers

Each enforcement adapter exposes `apply / remove / verify` and names the **real** API it
replaces. The four are registered in `LAYERS` so the apply step is a clean fan-out.
'''))

cells.append(code(r'''
# ---------------------------------------------------------------------------
# MOCK ServiceNow requests from GIS (Global Information Security)
# ---------------------------------------------------------------------------
REQUESTS = [
    {"number": "REQ0101", "indicator": "malware-c2.example",        "action": "deny",
     "scope": "enterprise", "duration_days": None, "requested_by": "soc.analyst",
     "justification": "Confirmed C2 from incident INC0456"},
    {"number": "REQ0102", "indicator": "vendor-portal.partner.com", "action": "allow",
     "scope": "finance-ou", "duration_days": 90, "requested_by": "ap.manager",
     "justification": "New AP vendor portal blocked by default category"},
    {"number": "REQ0103", "indicator": "microsoft.com",            "action": "deny",
     "scope": "enterprise", "duration_days": None, "requested_by": "helpdesk.t1",
     "justification": "User says 'microsoft popup' is malware"},
    {"number": "REQ0104", "indicator": "free-prizes-login.ru",     "action": "allow",
     "scope": "enterprise", "duration_days": 30, "requested_by": "marketing.intern",
     "justification": "Campaign landing page"},
    {"number": "REQ0105", "indicator": "203.0.113.66",             "action": "deny",
     "scope": "enterprise", "duration_days": None, "requested_by": "soc.analyst",
     "justification": "Scanning our perimeter"},
]

def snow_fetch_requests():
    return list(REQUESTS)
    # === REAL API === GET {SNOW}/api/now/table/sc_req_item?sysparm_query=cat_item=allowdeny^active=true

def snow_update(number, state, work_notes=""):
    audit("servicenow.update", number, {"state": state, "notes": work_notes[:70]})
    return {"number": number, "state": state}
    # === REAL API === PATCH {SNOW}/api/now/table/sc_req_item/{sys_id}

# ---------------------------------------------------------------------------
# MOCK threat-intel reputation (VirusTotal / Cisco Talos / URLhaus style)
# ---------------------------------------------------------------------------
_REPUTATION = {
    "malware-c2.example": {"verdict": "malicious", "score": 92, "category": "command-and-control"},
    "free-prizes-login.ru": {"verdict": "malicious", "score": 88, "category": "phishing"},
    "vendor-portal.partner.com": {"verdict": "clean", "score": 3, "category": "business"},
    "203.0.113.66": {"verdict": "suspicious", "score": 61, "category": "scanning"},
    "microsoft.com": {"verdict": "clean", "score": 0, "category": "technology"},
}

def threat_intel(indicator):
    return _REPUTATION.get(indicator, {"verdict": "unknown", "score": 50, "category": "uncategorized"})
    # === REAL API === VirusTotal /api/v3/domains/{d}; Talos; internal TIP (MISP/OpenCTI)

# ---------------------------------------------------------------------------
# Never-block list — blocking these breaks the business. Code-enforced.
# ---------------------------------------------------------------------------
CRITICAL_NEVER_BLOCK = {
    "microsoft.com", "windowsupdate.com", "office.com", "office365.com",
    "login.microsoftonline.com", "azure.com", "contoso.com", "okta.com",
    "google.com", "apple.com", "amazonaws.com",
}
'''))

cells.append(code(r'''
# ---------------------------------------------------------------------------
# Four enforcement-layer adapters. In-memory "applied state" lets verify() work.
# ---------------------------------------------------------------------------
_STATE = {"dns": {}, "ngfw": {}, "swg": {}, "edr": {}}

def _mk(layer, real_hint):
    def apply(indicator, action, **kw):
        _STATE[layer][indicator] = action
        ref = f"{layer}-{abs(hash((indicator, action))) % 100000}"
        audit(f"{layer}.apply", indicator, {"action": action, "ref": ref})
        return {"ok": True, "ref": ref}
        # === REAL API === {real_hint}
    def remove(indicator, **kw):
        _STATE[layer].pop(indicator, None)
        audit(f"{layer}.rollback", indicator)
        return {"ok": True}
    def verify(indicator, action, **kw):
        return _STATE[layer].get(indicator) == action
    apply.__doc__ = f"{layer.upper()} enforcement via: {real_hint}"
    return {"apply": apply, "remove": remove, "verify": verify, "real": real_hint}

LAYERS = {
    "dns":  _mk("dns",  "Cisco Umbrella POST /policies/destinationlists/{id}/destinations  OR Infoblox RPZ WAPI"),
    "ngfw": _mk("ngfw", "Palo Alto PAN-OS: append to External Dynamic List / custom URL category, then commit"),
    "swg":  _mk("swg",  "Zscaler ZIA /urlCategories/{id} custom URL category (+ /status activate)"),
    "edr":  _mk("edr",  "Microsoft Defender /api/indicators (ti indicator) OR CrowdStrike /iocs/entities/indicators/v1"),
}
print("Enforcement layers registered:", list(LAYERS))
'''))

cells.append(md(r'''
## 2. Triage: indicator type, reputation, and guardrails

The guardrails are deliberately *before* the model and *enforced in code*: the LLM plans
the change but cannot authorize blocking critical infrastructure or auto-allowing a
known-malicious site.
'''))

cells.append(code(r'''
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def classify_indicator(ind):
    if IPV4.match(ind):
        return "ip"
    if "://" in ind or "/" in ind:
        return "url"
    return "domain"

def registrable(domain):
    """Crude eTLD+1 for the never-block check (demo-grade; use tldextract in prod)."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def guardrail_verdict(req, itype, rep):
    """Return (verdict, reason): PROCEED / REFUSE / ESCALATE — overrides the LLM."""
    ind, action = req["indicator"], req["action"]
    if action == "deny" and itype in ("domain", "url"):
        host = ind.split("/")[0]
        if registrable(host) in CRITICAL_NEVER_BLOCK or host in CRITICAL_NEVER_BLOCK:
            return "REFUSE", f"{ind} is critical infrastructure — blocking is prohibited"
    if action == "allow" and rep["verdict"] == "malicious":
        return "ESCALATE", f"cannot auto-allow a known-malicious indicator (rep={rep['score']})"
    return "PROCEED", "passed guardrails"
'''))

cells.append(md('## 3. Agent state + planning schema'))

cells.append(code(r'''
Verdict = Literal["PROCEED", "REFUSE", "ESCALATE"]

class EnforcementPlan(BaseModel):
    request_id: str
    indicator: str
    action: Literal["allow", "deny"]
    indicator_type: Literal["domain", "url", "ip"]
    layers: list[Literal["dns", "ngfw", "swg", "edr"]] = Field(
        description="which enforcement layers apply for this indicator type")
    verdict: Verdict
    rationale: str

class AgentState(TypedDict):
    requests: list[dict]
    triaged: list[dict]
    plans: list[dict]
    approved: list[str]
    results: list[dict]
    report: dict
'''))

cells.append(code(r'''
# Default layer applicability by indicator type (DNS can't sinkhole a raw IP; etc.)
LAYERS_BY_TYPE = {"domain": ["dns", "ngfw", "swg", "edr"],
                  "url":    ["ngfw", "swg", "edr"],
                  "ip":     ["ngfw", "edr"]}

def rule_plan(req, itype, verdict, reason) -> EnforcementPlan:
    layers = LAYERS_BY_TYPE[itype] if verdict == "PROCEED" else []
    return EnforcementPlan(request_id=req["number"], indicator=req["indicator"],
                           action=req["action"], indicator_type=itype, layers=layers,
                           verdict=verdict, rationale=reason)
'''))

cells.append(md('## 4. Graph nodes'))

cells.append(code(r'''
def n_intake(state: AgentState) -> dict:
    reqs = snow_fetch_requests()
    audit("intake.requests", "servicenow", {"count": len(reqs)})
    return {"requests": reqs}

def n_triage(state: AgentState) -> dict:
    triaged = []
    for req in state["requests"]:
        itype = classify_indicator(req["indicator"])
        rep = threat_intel(req["indicator"])
        verdict, reason = guardrail_verdict(req, itype, rep)
        triaged.append({**req, "itype": itype, "reputation": rep,
                        "guardrail": verdict, "guardrail_reason": reason})
        print(f"[triage] {req['number']} {req['action']:5s} {req['indicator']:28s} "
              f"type={itype:6s} rep={rep['verdict']:10s} -> {verdict} ({reason})")
    return {"triaged": triaged}
'''))

cells.append(code(r'''
PLAN_SYS = (
    "You are a network security engineer fulfilling an allow/deny request across four "
    "enforcement layers: dns, ngfw, swg, edr. Choose the layers that apply for the "
    "indicator type (domains -> all four; URLs -> ngfw/swg/edr; raw IPs -> ngfw/edr, since "
    "DNS cannot sinkhole a bare IP). Respect the provided guardrail verdict: if it is "
    "REFUSE or ESCALATE, return that verdict with NO layers. Give a one-line rationale."
)

def n_plan(state: AgentState) -> dict:
    plans = []
    for t in state["triaged"]:
        demo = rule_plan(t, t["itype"], t["guardrail"], t["guardrail_reason"])
        user = json.dumps({k: t[k] for k in ("number", "indicator", "action", "scope",
                          "itype", "reputation", "guardrail", "guardrail_reason")}, default=str)
        plan = llm_structured(PLAN_SYS, "Plan this request:\n" + user, EnforcementPlan, demo)
        # Guardrail wins regardless of the model: strip layers if not PROCEED.
        if t["guardrail"] != "PROCEED":
            plan.verdict, plan.layers = t["guardrail"], []
        p = plan.model_dump(); p["_req"] = t
        plans.append(p)
        print(f"[plan]   {p['request_id']} {p['verdict']:8s} layers={p['layers']}")
    return {"plans": plans}
'''))

cells.append(code(r'''
def n_approval(state: AgentState) -> dict:
    actionable = [p for p in state["plans"] if p["verdict"] == "PROCEED"]
    # Route REFUSE/ESCALATE out to humans immediately (no enforcement).
    for p in state["plans"]:
        if p["verdict"] == "REFUSE":
            snow_update(p["request_id"], "closed_rejected", p["rationale"])
        elif p["verdict"] == "ESCALATE":
            snow_update(p["request_id"], "escalated", p["rationale"])
    if not actionable:
        return {"approved": []}
    decision = interrupt({
        "type": "approve_enforcement",
        "summary": f"{len(actionable)} change(s) ready to enforce",
        "changes": [{"request": p["request_id"], "action": p["action"],
                     "indicator": p["indicator"], "layers": p["layers"],
                     "reputation": p["_req"]["reputation"]["verdict"]} for p in actionable],
        "note": "Allow-list changes weaken controls — review before approving.",
        "instructions": "resume with {'approved': [request ids]} or {'approved': 'ALL'}",
    })
    approved = decision.get("approved", []) if isinstance(decision, dict) else []
    if approved == "ALL":
        approved = [p["request_id"] for p in actionable]
    audit("human.approval", "enforcement-batch", {"approved": approved})
    return {"approved": approved}
'''))

cells.append(code(r'''
def _apply_one(plan):
    """Apply a plan across its layers; roll back everything on any failure (atomicity)."""
    applied = []
    try:
        for layer in plan["layers"]:
            res = LAYERS[layer]["apply"](plan["indicator"], plan["action"])
            if not res.get("ok"):
                raise RuntimeError(f"{layer} apply failed")
            applied.append(layer)
        return {"ok": True, "applied": applied}
    except Exception as e:
        for layer in applied:                      # rollback partial change
            LAYERS[layer]["remove"](plan["indicator"])
        audit("apply.rolled_back", plan["indicator"], {"error": str(e), "undone": applied})
        return {"ok": False, "applied": [], "error": str(e)}

def n_apply(state: AgentState) -> dict:
    by_id = {p["request_id"]: p for p in state["plans"]}
    results = []
    for rid in state["approved"]:
        plan = by_id[rid]
        outcome = _apply_one(plan)
        verified = {l: LAYERS[l]["verify"](plan["indicator"], plan["action"])
                    for l in outcome["applied"]}
        ok = outcome["ok"] and all(verified.values())
        snow_update(rid, "closed_complete" if ok else "work_in_progress",
                    f"Enforced {plan['action']} on {sorted(verified)}" if ok else "apply/verify failed")
        results.append({"request_id": rid, "indicator": plan["indicator"],
                        "action": plan["action"], "applied": outcome["applied"],
                        "verified": verified, "ok": ok})
        print(f"[apply]  {rid} {plan['action']} {plan['indicator']:28s} "
              f"layers={outcome['applied']} verified={all(verified.values())}")
    return {"results": results}

def n_report(state: AgentState) -> dict:
    enforced = [r for r in state["results"] if r["ok"]]
    report = {
        "requests": len(state["requests"]),
        "enforced": [r["request_id"] for r in enforced],
        "refused": [p["request_id"] for p in state["plans"] if p["verdict"] == "REFUSE"],
        "escalated": [p["request_id"] for p in state["plans"] if p["verdict"] == "ESCALATE"],
        "layer_changes": sum(len(r["applied"]) for r in enforced),
    }
    print(f"[report] enforced {len(enforced)} request(s), "
          f"{report['layer_changes']} layer changes; "
          f"{len(report['refused'])} refused, {len(report['escalated'])} escalated")
    return {"report": report}
'''))

cells.append(md('## 5. Build & compile the graph'))

cells.append(code(r'''
g = StateGraph(AgentState)
for name, fn in [("intake", n_intake), ("triage", n_triage), ("plan", n_plan),
                 ("approval", n_approval), ("apply", n_apply), ("report", n_report)]:
    g.add_node(name, fn)
g.add_edge(START, "intake")
g.add_edge("intake", "triage")
g.add_edge("triage", "plan")
g.add_edge("plan", "approval")
g.add_edge("approval", "apply")
g.add_edge("apply", "report")
g.add_edge("report", END)
app = g.compile(checkpointer=MemorySaver())
print("Graph compiled:", list(app.get_graph().nodes))
'''))

cells.append(md('## 6. Run it'))

cells.append(code(r'''
AUDIT.clear()
config = {"configurable": {"thread_id": "allowdeny-run-2026-06-02"}}
init = {"requests": [], "triaged": [], "plans": [], "approved": [], "results": [], "report": {}}
result = app.invoke(init, config)

print("\n=== PAUSED FOR APPROVAL ===")
intr = result["__interrupt__"][0].value
print(intr["summary"], "--", intr["note"])
for c in intr["changes"]:
    print(f"  - {c['request']}  {c['action']:5s} {c['indicator']:28s} "
          f"layers={c['layers']}  rep={c['reputation']}")
'''))

cells.append(code(r'''
# Human approves both PROCEED changes (the deny C2 + the vendor allow). The refused
# (microsoft.com) and escalated (malicious allow) requests never reach this gate.
final = app.invoke(Command(resume={"approved": "ALL"}), config)
print("\n=== FINAL REPORT ===")
print(json.dumps(final["report"], indent=2))
'''))

cells.append(md('## 7. Results + audit trail'))

cells.append(code(r'''
rows = [{"request": p["request_id"], "action": p["action"], "indicator": p["indicator"],
         "type": p["indicator_type"], "verdict": p["verdict"], "layers": p["layers"],
         "rationale": p["rationale"]} for p in final["plans"]]
display(pd.DataFrame(rows))
print()
display(pd.DataFrame(AUDIT)[["action", "target", "detail"]])
'''))

cells.append(md(r'''
## 8. Productionizing

**Wire the real layers** (replace each `# === REAL API ===`):
- *DNS*: Cisco Umbrella destination lists, or Infoblox RPZ via WAPI / internal AD DNS.
- *NGFW*: Palo Alto External Dynamic Lists (no commit needed) or custom URL categories;
  Fortinet web filter profiles.
- *SWG*: Zscaler ZIA custom URL categories (remember the activate/commit step); Netskope.
- *EDR*: Microsoft Defender for Endpoint TI indicators; CrowdStrike Falcon IOC API.

**Why fan-out + rollback** — partial enforcement is a security gap (blocked on the proxy,
reachable via DNS). `_apply_one` is atomic per request: any layer failure rolls back the
rest, and `verify()` confirms enforcement before the ticket is closed.

**Guardrails are the point** — the demo refuses `deny microsoft.com` (critical infra) and
escalates `allow free-prizes-login.ru` (known-malicious). These are code rules the model
cannot override.

**Hardening**
- Use **eTLD+1 (`tldextract`) + IDN/punycode normalization** so look-alike and subdomain
  tricks can't dodge the never-block list.
- **Expire** allow-list entries on `duration_days` (a scheduled reconcile job) so temporary
  exceptions don't live forever — the most common audit finding.
- Make every adapter idempotent; key entries by request id so re-runs and removals are clean.
- Surface the approval as a Teams Adaptive Card / SNOW approval; persist the LangGraph
  checkpointer so the gate can resume later. Notify the requester on completion.
'''))

build(OUT, cells, "Problem 4 — Site Allow/Deny-List Orchestration Agent")
validate_code_syntax(OUT)
