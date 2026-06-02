"""Builder for 03_CVE_Prioritization_RAG_GraphRAG_Agent.ipynb
Cell convention: outer delimiter r'''...''' ; inner code uses only \"\"\" docstrings.
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from nbtools import md, code, build, validate_code_syntax

OUT = os.path.join(os.path.dirname(__file__), "..", "03_CVE_Prioritization_RAG_GraphRAG_Agent.ipynb")
cells = []

cells.append(md(r'''
# Problem 3 — CVE Prioritization & Remediation Agent (RAG + GraphRAG)

> *Searching for CVEs can be cumbersome and time-consuming when it comes to identifying the
> vulnerability and its associated remediation. Create an AI agent that you could just give
> a CVE or a list of CVEs, and have the agent prioritize and give solutions to the related
> vulnerability. If possible, adapt the RAG and graphRAG methods in
> `JH_AI_P4/FullCode_Notebook.ipynb` ... and identify any enhancements ... for the content
> of CVEs.*

## What this agent does
Give it one CVE or a list. It:
1. **Enriches** each CVE with authoritative signals — NVD (CVSS, CWE, CPE), **CISA KEV**
   (is it being exploited *right now*?), and **EPSS** (probability it will be).
2. **Builds a knowledge graph** (GraphRAG) linking CVE ↔ CWE ↔ Product ↔ Patch ↔ **your
   assets**, so it can compute *blast radius* and surface *related* CVEs.
3. **Prioritizes** with a transparent, SSVC-style score that fuses CVSS + EPSS + KEV +
   **your** asset exposure — not a generic severity number.
4. **Retrieves remediation** with dense RAG over advisory text and **synthesizes a grounded,
   cited fix** per CVE.
5. Optionally **opens ServiceNow remediation tasks** for the "act now" set (human-approved).

```
 CVE list ─► enrich ─► build graph ─► prioritize ─► remediate ─► [approve] ─► tickets ─► report
            (NVD/KEV/  (CVE-CWE-Prod- (CVSS+EPSS+   (RAG +graph  interrupt()  (SNOW)
             EPSS)      Asset-Patch)   KEV+exposure) +LLM, cited)
```

## How this adapts — and upgrades — the `JH_AI_P4` reference
The energy-report notebook is a strong, general **RAG/GraphRAG-for-prose** pipeline. CVEs
are a different beast: highly **structured**, **relational**, **time-sensitive**, and the
goal is a **decision (rank + fix)**, not a well-written paragraph. The mapping:

| `JH_AI_P4` building block | Reused here | CVE-specific enhancement |
|---|---|---|
| `rag_harness` (chunk→embed→Chroma→retrieve→cite) | Dense retrieval over remediation advisories, with citations | Add **structured pre-filters** (CPE / CVSS / date) before semantic search |
| `graph_rag` (LLMGraphTransformer → Neo4j, constrained node/rel schema) | Same constrained-schema graph idea | **Deterministic ingest from NVD JSON** — no LLM extraction for fields that are already structured (precision↑, cost↓); LLM only for prose |
| Reranking / contextual retrieval (§6.12) | Optional cross-encoder rerank | Useful when many near-duplicate advisories exist |
| Chain-of-Verification (§6.9) | Grounding check on the proposed fix | Verify the fix cites an **authoritative** source (NVD/vendor/CISA) |
| RAGAS answer-quality eval | Retrieval sanity check | Replace "answer quality" with a **prioritization/decision** objective |
| (n/a) | — | **Live signals** (KEV/EPSS/NVD APIs) + **asset-context join** (your CMDB) + **quantitative prioritization** |

The full enhancement rationale is in the final section. Everything below **runs offline**
(mock NVD/KEV/EPSS/CMDB; local embeddings; in-memory graph) with real-API stubs marked
`# === REAL API ===`.
'''))

cells.append(md(r'''
## 0. Setup
Runs with **no credentials and no GPU**. Embeddings use `sentence-transformers` when
installed (faithful to the reference's HuggingFace embedder) and fall back to a
deterministic hashing embedding otherwise, so the whole pipeline is runnable anywhere. Set
an LLM key in `.env` to turn on real remediation synthesis.
'''))

cells.append(code(r'''
import os, re, json, hashlib, datetime as dt
from typing import TypedDict, Literal, Optional
import numpy as np
import pandas as pd
import networkx as nx
from pydantic import BaseModel, Field

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
def audit(action, target, detail=None, actor="cve-agent"):
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "actor": actor, "action": action, "target": target, "detail": detail or {}}
    AUDIT.append(rec)
    return rec

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
      else "OFFLINE deterministic stub (set an API key in .env to enable real synthesis)")

def llm_structured(system, user, schema, demo):
    if LLM is None:
        return demo
    return LLM.with_structured_output(schema).invoke(
        [SystemMessage(content=system), HumanMessage(content=user)])
'''))

cells.append(md(r'''
## 1. Data sources — NVD, CISA KEV, EPSS, and your asset inventory (CMDB)

Mocked with **realistic, well-known CVEs** so the demo is relatable; values are illustrative,
not live. Each accessor names the real feed it replaces. The **asset inventory** is what
makes prioritization *yours* — the same CVE is an emergency on an internet-facing box and a
backlog item on an isolated one.
'''))

cells.append(code(r'''
# ---------------------------------------------------------------------------
# MOCK NVD records.  cwe / cpe (products) / cvss are the STRUCTURED fields we
# ingest deterministically into the graph (no LLM needed). `fix` is the
# authoritative remediation; `advisories` seed the RAG corpus.
# ---------------------------------------------------------------------------
NVD = {
  "CVE-2021-44228": {"desc": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints (Log4Shell), enabling remote code execution.",
    "cvss_base": 10.0, "cwe": "CWE-917", "products": ["apache-log4j"], "published": "2021-12-10",
    "fix": "Upgrade Log4j to 2.17.1+. Interim: remove the JndiLookup class or set log4j2.formatMsgNoLookups=true."},
  "CVE-2017-0144": {"desc": "The SMBv1 server in Microsoft Windows mishandles specially crafted packets, allowing remote code execution (EternalBlue / MS17-010).",
    "cvss_base": 8.1, "cwe": "CWE-20", "products": ["microsoft-windows-smbv1"], "published": "2017-03-16",
    "fix": "Apply MS17-010. Disable SMBv1 entirely. Block 445/tcp at the perimeter."},
  "CVE-2014-0160": {"desc": "The TLS heartbeat extension in OpenSSL allows remote attackers to read process memory (Heartbleed), exposing keys and secrets.",
    "cvss_base": 7.5, "cwe": "CWE-125", "products": ["openssl"], "published": "2014-04-07",
    "fix": "Upgrade OpenSSL to 1.0.1g+. Reissue and revoke certificates; rotate exposed secrets."},
  "CVE-2019-0708": {"desc": "A use-after-free in Remote Desktop Services (BlueKeep) allows unauthenticated remote code execution via crafted RDP requests.",
    "cvss_base": 9.8, "cwe": "CWE-416", "products": ["microsoft-rdp"], "published": "2019-05-14",
    "fix": "Apply the RDP security update. Enable Network Level Authentication. Restrict 3389/tcp."},
  "CVE-2023-23397": {"desc": "Microsoft Outlook elevation-of-privilege: a crafted reminder with a UNC path leaks Net-NTLMv2 hashes with no user interaction.",
    "cvss_base": 9.8, "cwe": "CWE-294", "products": ["microsoft-outlook"], "published": "2023-03-14",
    "fix": "Install the Outlook security update. Block outbound TCP 445. Run Microsoft's script to scan mailboxes for malicious reminders."},
  "CVE-2020-1472": {"desc": "Netlogon elevation-of-privilege (Zerologon): a flawed use of AES-CFB8 lets an attacker take over a domain controller.",
    "cvss_base": 10.0, "cwe": "CWE-330", "products": ["microsoft-netlogon"], "published": "2020-08-11",
    "fix": "Apply the Aug 2020 DC updates and enforce secure RPC (DC enforcement mode)."},
  "CVE-2018-0171": {"desc": "Cisco IOS/IOS XE Smart Install buffer overflow allows unauthenticated remote code execution or DoS.",
    "cvss_base": 9.8, "cwe": "CWE-787", "products": ["cisco-ios"], "published": "2018-03-28",
    "fix": "Disable Smart Install (no vstack). Upgrade IOS. Restrict 4786/tcp."},
  "CVE-2022-3786": {"desc": "OpenSSL X.509 punycode buffer overflow (4-byte stack overrun) reachable during certificate verification.",
    "cvss_base": 7.5, "cwe": "CWE-787", "products": ["openssl"], "published": "2022-11-01",
    "fix": "Upgrade OpenSSL to 3.0.7+."},
  "CVE-2021-0009": {"desc": "Low-severity information exposure in a sample logging library under uncommon configuration.",
    "cvss_base": 3.5, "cwe": "CWE-200", "products": ["sample-logging-lib"], "published": "2021-02-09",
    "fix": "Upgrade sample-logging-lib to the patched release."},
}

# Authoritative remediation advisories -> RAG corpus (source-tagged for citations).
ADVISORIES = [
  ("NVD:CVE-2021-44228", "CVE-2021-44228", "Log4Shell remediation: upgrade Apache Log4j to 2.17.1 or later. If you cannot upgrade immediately, remove the JndiLookup class from the classpath (zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class). Setting formatMsgNoLookups is insufficient on some versions."),
  ("CISA-KEV", "CVE-2021-44228", "Log4Shell is in the CISA Known Exploited Vulnerabilities catalog with mass exploitation observed. Treat as emergency change; hunt for exploitation, not just patch."),
  ("NVD:CVE-2017-0144", "CVE-2017-0144", "EternalBlue remediation: apply Microsoft MS17-010 to all Windows hosts. Disable SMBv1 via Set-SmbServerConfiguration -EnableSMB1Protocol $false and Group Policy. Block inbound 445/tcp at the perimeter and segment internally."),
  ("vendor-KB:OpenSSL", "CVE-2014-0160", "Heartbleed remediation: upgrade to a fixed OpenSSL (1.0.1g+). Because private keys may have leaked, reissue all certificates with new keys and revoke the old ones, then rotate any secrets exposed to the vulnerable service."),
  ("NVD:CVE-2019-0708", "CVE-2019-0708", "BlueKeep remediation: install the RDP security update on Windows 7/Server 2008 era systems. Enable Network Level Authentication (NLA) to require auth before session establishment, and restrict RDP (3389/tcp) to a jump host / VPN."),
  ("MSRC:CVE-2023-23397", "CVE-2023-23397", "Outlook EoP remediation: install the security update. As mitigation, add users to the Protected Users security group or block outbound TCP 445 so Net-NTLMv2 cannot egress. Run the Microsoft CVE-2023-23397 script to find and clean malicious reminder items."),
  ("MSRC:CVE-2020-1472", "CVE-2020-1472", "Zerologon remediation: apply the August 2020 (and follow-up) domain controller updates, then enable DC enforcement mode so vulnerable Netlogon secure-channel connections are denied. Monitor event IDs 5827-5831."),
  ("Cisco-SA:CVE-2018-0171", "CVE-2018-0171", "Smart Install remediation: disable the feature with 'no vstack' on switches that do not need it, upgrade IOS/IOS XE to a fixed release, and block 4786/tcp. Use the Cisco Smart Install scanner to find exposed devices."),
  ("NVD:CVE-2022-3786", "CVE-2022-3786", "OpenSSL punycode overflow remediation: upgrade to OpenSSL 3.0.7. Exploitation requires a malicious certificate chain to be verified; risk is highest for clients doing mutual TLS."),
  ("hardening:SMBv1", None, "General hardening: SMBv1 is deprecated and should be removed enterprise-wide; it underlies multiple wormable exploits. Inventory with Get-WindowsOptionalFeature and remove FS-SMB1."),
  ("hardening:RDP", None, "General hardening: never expose RDP (3389/tcp) directly to the internet. Require a VPN or RD Gateway, enforce NLA and MFA, and rate-limit/lock out brute force."),
  ("hardening:NTLM", None, "General hardening: restrict NTLM and block outbound SMB (445/tcp) at the egress firewall to prevent credential-leak and relay attacks across several Windows CVEs."),
]

def nvd_lookup(cve):
    rec = NVD.get(cve)
    return dict(rec, cve=cve) if rec else None
    # === REAL API === GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}
    #   (set NVD_API_KEY header to raise the rate limit). Parse metrics.cvssMetricV31,
    #   weaknesses[].description (CWE), configurations[].nodes[].cpeMatch (CPE).
'''))

cells.append(code(r'''
# CISA KEV (actively exploited) and EPSS (exploit-prediction probability, 0-1).
KEV = {"CVE-2021-44228", "CVE-2017-0144", "CVE-2014-0160", "CVE-2019-0708",
       "CVE-2023-23397", "CVE-2020-1472", "CVE-2018-0171"}
EPSS = {"CVE-2021-44228": 0.975, "CVE-2017-0144": 0.945, "CVE-2014-0160": 0.973,
        "CVE-2019-0708": 0.964, "CVE-2023-23397": 0.62, "CVE-2020-1472": 0.94,
        "CVE-2018-0171": 0.31, "CVE-2022-3786": 0.05, "CVE-2021-0009": 0.01}

def kev_check(cve):
    return cve in KEV
    # === REAL API === GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

def epss_score(cve):
    return EPSS.get(cve, 0.05)
    # === REAL API === GET https://api.first.org/data/v1/epss?cve={cve}

# ---------------------------------------------------------------------------
# MOCK asset inventory (from the ServiceNow CMDB): product -> exposure.
# This is the join that turns generic severity into YOUR risk.
# ---------------------------------------------------------------------------
INVENTORY = {
    "apache-log4j":            {"asset_count": 40,  "internet_facing": 6},
    "microsoft-windows-smbv1": {"asset_count": 12,  "internet_facing": 0},
    "openssl":                 {"asset_count": 80,  "internet_facing": 10},
    "microsoft-rdp":           {"asset_count": 25,  "internet_facing": 3},
    "microsoft-outlook":       {"asset_count": 500, "internet_facing": 0},
    "microsoft-netlogon":      {"asset_count": 4,   "internet_facing": 0},
    "cisco-ios":               {"asset_count": 8,   "internet_facing": 8},
    # 'sample-logging-lib' intentionally absent -> we don't run it -> exposure 0
}

def asset_exposure(products):
    n = sum(INVENTORY.get(p, {}).get("asset_count", 0) for p in products)
    inet = sum(INVENTORY.get(p, {}).get("internet_facing", 0) for p in products)
    return {"asset_count": n, "internet_facing": inet}
    # === REAL API === ServiceNow CMDB: GET cmdb_ci_spkg / software install records joined
    #   to cmdb_ci_computer; flag internet_facing from the network zone / discovery data.

print("Data sources ready:", len(NVD), "CVEs,", len(ADVISORIES), "advisories,",
      len(INVENTORY), "inventoried products")
'''))

cells.append(md(r'''
## 2. RAG layer — dense retrieval over remediation advisories

Adapted from the reference's `rag_harness` (chunk → embed → vector store → retrieve →
**cited** context). The corpus is small, so we use a transparent NumPy cosine store;
the reference's Chroma + `bge` embedder is shown as the production path. Embeddings use
`sentence-transformers` when available, else a deterministic hashing fallback.
'''))

cells.append(code(r'''
def get_embedder():
    """Prefer sentence-transformers (faithful to the reference); fall back to hashing."""
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2")
        def embed(texts):
            return np.asarray(model.encode(list(texts), normalize_embeddings=True),
                              dtype="float32")
        return embed, "sentence-transformers/all-MiniLM-L6-v2"
    except Exception:
        DIM = 384
        def embed(texts):
            out = np.zeros((len(texts), DIM), dtype="float32")
            for i, t in enumerate(texts):
                for tok in re.findall(r"[a-z0-9]+", t.lower()):
                    h = int(hashlib.md5(tok.encode()).hexdigest(), 16) % DIM
                    out[i, h] += 1.0
                nrm = np.linalg.norm(out[i]) or 1.0
                out[i] /= nrm
            return out
        return embed, "hashing-fallback-384d (pip install sentence-transformers for real embeddings)"

EMBED, EMBED_NAME = get_embedder()
print("Embedder:", EMBED_NAME)

# === REAL API (reference parity) ===
# from langchain_huggingface import HuggingFaceEmbeddings
# from langchain_chroma import Chroma
# emb = HuggingFaceEmbeddings(model_name="BAAI/bge-base-en-v1.5",
#                             encode_kwargs={"normalize_embeddings": True})
# store = Chroma(collection_name="cve_advisories", embedding_function=emb,
#                persist_directory="chroma_stores/cve")
'''))

cells.append(code(r'''
class NumpyVectorStore:
    """Minimal cosine-similarity store (vectors are L2-normalized -> dot == cosine)."""
    def __init__(self, embed):
        self.embed = embed
        self.docs, self.mat = [], None

    def add(self, docs):
        self.docs.extend(docs)
        V = self.embed([d["text"] for d in docs])
        self.mat = V if self.mat is None else np.vstack([self.mat, V])

    def search(self, query, k=4, where=None):
        cand = [i for i, d in enumerate(self.docs) if (where(d) if where else True)]
        if not cand:
            return []
        q = self.embed([query])[0]
        sims = self.mat[cand] @ q
        order = np.argsort(sims)[::-1][:k]
        return [(self.docs[cand[j]], float(sims[j])) for j in order]

# Chunk = one advisory (already short). meta carries source + cve for citation/filtering.
VS = NumpyVectorStore(EMBED)
VS.add([{"text": text, "meta": {"source": src, "cve": cve}}
        for (src, cve, text) in ADVISORIES])

def format_context(hits):
    """Cited context block, mirroring the reference's [source] formatting."""
    return "\n\n".join(f"[{d['meta']['source']}] {d['text']}" for d, _ in hits)

# sanity check
for d, s in VS.search("how do I fix log4shell remote code execution", k=2):
    print(f"  {s:.3f}  [{d['meta']['source']}] {d['text'][:70]}...")
'''))

cells.append(md(r'''
## 3. GraphRAG layer — a CVE knowledge graph

Adapted from the reference's `graph_rag`, which used `LLMGraphTransformer` with a
**constrained node/relationship schema** to extract a graph from prose. **Enhancement:**
CVE data is already structured, so we ingest it **deterministically** (no LLM, no
extraction error) and reserve the LLM for the unstructured advisory text. The schema:

```
        (Vendor)
           ▲ MADE_BY
        (Product) ◄──AFFECTS── (CVE) ──INSTANCE_OF──► (CWE)
           ▲ RUNS                │   └──RELATED_TO──► (CVE)   # shared CWE / product
        (Asset)            REMEDIATED_BY
                                 ▼
                              (Patch)        CVE.kev / CVE.epss = exploitation signals
```

This unlocks queries flat RAG cannot answer: **blast radius** (which of *our* assets does a
CVE reach?) and **related CVEs** (fix one, check its neighbors).
'''))

cells.append(code(r'''
# Constrained schema (mirrors the reference's ALLOWED_NODES / ALLOWED_RELATIONSHIPS idea).
ALLOWED_NODES = ["CVE", "CWE", "Product", "Vendor", "Patch", "Asset"]
ALLOWED_RELATIONSHIPS = ["AFFECTS", "INSTANCE_OF", "REMEDIATED_BY", "RUNS", "RELATED_TO"]

def build_cve_graph(cves):
    """Deterministic ingest of structured NVD fields into an in-memory knowledge graph."""
    G = nx.MultiDiGraph()
    for cve in cves:
        rec = nvd_lookup(cve)
        if not rec:
            continue
        G.add_node(cve, kind="CVE", cvss=rec["cvss_base"], kev=kev_check(cve),
                   epss=epss_score(cve))
        G.add_node(rec["cwe"], kind="CWE")
        G.add_edge(cve, rec["cwe"], rel="INSTANCE_OF")
        patch = "PATCH:" + cve
        G.add_node(patch, kind="Patch", fix=rec["fix"])
        G.add_edge(cve, patch, rel="REMEDIATED_BY")
        for prod in rec["products"]:
            G.add_node(prod, kind="Product")
            G.add_edge(cve, prod, rel="AFFECTS")
            exp = INVENTORY.get(prod)
            if exp:
                asset = "ASSETS:" + prod
                if not G.has_node(asset):
                    G.add_node(asset, kind="Asset", **exp)
                if not G.has_edge(asset, prod):   # avoid duplicate RUNS edges (shared products)
                    G.add_edge(asset, prod, rel="RUNS")
    # RELATED_TO: connect CVEs that share a CWE or a Product
    cve_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "CVE"]
    for a in cve_nodes:
        for b in cve_nodes:
            if a >= b:
                continue
            shared = set(G.successors(a)) & set(G.successors(b))
            if any(G.nodes[s]["kind"] in ("CWE", "Product") for s in shared):
                G.add_edge(a, b, rel="RELATED_TO")
                G.add_edge(b, a, rel="RELATED_TO")
    return G

# === REAL API (reference parity) ===
# from langchain_neo4j import Neo4jGraph
# g = Neo4jGraph(url=get_secret("NEO4J_URI"), username=..., password=...)
# # Deterministic MERGE from NVD JSON (instead of LLMGraphTransformer on prose):
# g.query("MERGE (c:CVE {id:$id}) SET c.cvss=$cvss, c.kev=$kev, c.epss=$epss", params=...)
# g.query("MATCH (c:CVE{id:$id}),(p:Product{name:$p}) MERGE (c)-[:AFFECTS]->(p)", ...)
print("Graph schema:", ALLOWED_NODES, "/", ALLOWED_RELATIONSHIPS)
'''))

cells.append(code(r'''
def _rel_edges(G, n, rel, direction="out"):
    it = G.out_edges(n, data=True) if direction == "out" else G.in_edges(n, data=True)
    return [(v if direction == "out" else u) for (u, v, d) in it if d.get("rel") == rel]

def blast_radius(G, cve):
    """Which of OUR assets a CVE reaches, via AFFECTS -> Product <- RUNS Asset."""
    products = set(_rel_edges(G, cve, "AFFECTS"))
    assets = set()
    for p in products:
        assets.update(_rel_edges(G, p, "RUNS", direction="in"))
    total = sum(G.nodes[a].get("asset_count", 0) for a in assets)
    inet = sum(G.nodes[a].get("internet_facing", 0) for a in assets)
    return {"products": sorted(products), "asset_count": total, "internet_facing": inet}

def related_cves(G, cve):
    return sorted(set(_rel_edges(G, cve, "RELATED_TO")))

def graph_remediation(G, cve):
    patches = _rel_edges(G, cve, "REMEDIATED_BY")
    return G.nodes[patches[0]]["fix"] if patches else None

# demo
_G = build_cve_graph(list(NVD))
print("blast_radius(CVE-2014-0160):", blast_radius(_G, "CVE-2014-0160"))
print("related_cves(CVE-2014-0160):", related_cves(_G, "CVE-2014-0160"))
'''))

cells.append(md(r'''
## 4. Prioritization engine — CVSS + EPSS + KEV + your exposure (SSVC-style)

The reference optimized **answer quality** (RAGAS). For CVEs the deliverable is a
**decision**: what to fix first. We fuse four transparent signals into a score and an
SSVC-style action tier. KEV (actively exploited) and internet-facing exposure dominate —
a medium-CVSS bug under mass exploitation outranks a "critical" one nobody is using.
'''))

cells.append(code(r'''
def risk_score(rec):
    cvss = rec["cvss_base"] / 10.0
    epss = rec["epss"]
    kev = 1.0 if rec["kev"] else 0.0
    exposure = min(rec["exposure"]["internet_facing"], 5) / 5.0
    score = 0.30 * cvss + 0.25 * epss + 0.30 * kev + 0.15 * exposure
    return round(score, 3)

def ssvc_decision(rec):
    """ACT (immediate) / ATTEND (near-term) / TRACK (backlog)."""
    inet = rec["exposure"]["internet_facing"]
    if rec["asset_count"] == 0:
        return "TRACK"                      # we don't even run it
    if rec["kev"] or (rec["epss"] >= 0.5 and inet > 0):
        return "ACT"
    if rec["cvss_base"] >= 7.0 or rec["epss"] >= 0.2:
        return "ATTEND"
    return "TRACK"

DECISION_RANK = {"ACT": 0, "ATTEND": 1, "TRACK": 2}
'''))

cells.append(md('## 5. Agent state + schemas'))

cells.append(code(r'''
class RemediationBrief(BaseModel):
    cve: str
    decision: Literal["ACT", "ATTEND", "TRACK"]
    summary: str = Field(description="2-3 sentences: what it is and why this priority")
    steps: list[str] = Field(description="concrete remediation steps, most important first")
    citations: list[str] = Field(description="advisory sources backing the steps")

class AgentState(TypedDict):
    input_cves: list[str]
    enriched: list[dict]
    prioritized: list[dict]
    briefs: list[dict]
    approved: list[str]
    tickets: list[dict]
    report: dict
'''))

cells.append(md('## 6. Graph nodes'))

cells.append(code(r'''
def n_enrich(state: AgentState) -> dict:
    enriched = []
    for cve in state["input_cves"]:
        rec = nvd_lookup(cve)
        if not rec:
            audit("enrich.miss", cve); continue
        exp = asset_exposure(rec["products"])
        enriched.append({"cve": cve, "desc": rec["desc"], "cvss_base": rec["cvss_base"],
                         "cwe": rec["cwe"], "products": rec["products"], "fix": rec["fix"],
                         "kev": kev_check(cve), "epss": epss_score(cve),
                         "exposure": exp, "asset_count": exp["asset_count"]})
        audit("enrich.ok", cve, {"kev": kev_check(cve), "epss": epss_score(cve)})
    print(f"[enrich] {len(enriched)} CVEs enriched (NVD + KEV + EPSS + exposure)")
    return {"enriched": enriched}

def n_graph(state: AgentState) -> dict:
    G = build_cve_graph([e["cve"] for e in state["enriched"]])
    for e in state["enriched"]:
        e["blast_radius"] = blast_radius(G, e["cve"])
        e["related_cves"] = related_cves(G, e["cve"])
    print(f"[graph] built graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return {"enriched": state["enriched"]}
'''))

cells.append(code(r'''
def n_prioritize(state: AgentState) -> dict:
    scored = []
    for e in state["enriched"]:
        e = dict(e)
        e["risk_score"] = risk_score(e)
        e["decision"] = ssvc_decision(e)
        scored.append(e)
    scored.sort(key=lambda x: (DECISION_RANK[x["decision"]], -x["risk_score"]))
    print("[prioritize] ranked:")
    for e in scored:
        print(f"   {e['decision']:7s} score={e['risk_score']:.3f}  {e['cve']:16s} "
              f"kev={e['kev']!s:5s} epss={e['epss']:.2f} "
              f"assets={e['asset_count']} inet={e['exposure']['internet_facing']}")
    return {"prioritized": scored}
'''))

cells.append(code(r'''
REMEDIATE_SYS = (
    "You are a vulnerability-management analyst. Using ONLY the provided advisory excerpts "
    "and structured facts, write a concise remediation brief. Lead with the single most "
    "effective action. Every step must be grounded in the excerpts; cite their [source] "
    "tags. Be specific and operational."
)

def synth_brief(e) -> RemediationBrief:
    """RAG-retrieve remediation for one CVE, then synthesize a cited brief (LLM or fallback)."""
    # Hybrid retrieval: STRUCTURED pre-filter (this CVE's authoritative advisories) +
    # dense search; fall back to general hardening docs only if no specific advisory exists.
    query = e["desc"] + " remediation fix"
    hits = VS.search(query, k=4, where=lambda d: d["meta"]["cve"] == e["cve"])
    if not hits:
        hits = VS.search(query, k=3, where=lambda d: d["meta"]["cve"] is None)
    context = format_context(hits)
    citations = sorted({d["meta"]["source"] for d, _ in hits})
    user = (f"CVE: {e['cve']} (CVSS {e['cvss_base']}, {e['cwe']}, KEV={e['kev']}, "
            f"EPSS={e['epss']})\nAffected products: {e['products']}; "
            f"our exposure: {e['exposure']}; related CVEs: {e['related_cves']}\n\n"
            f"Advisory excerpts:\n{context}")
    # Deterministic offline fallback: structured fix + retrieved steps.
    demo = RemediationBrief(
        cve=e["cve"], decision=e["decision"],
        summary=(f"{e['cve']} ({e['cwe']}, CVSS {e['cvss_base']}). "
                 f"{'Actively exploited (CISA KEV). ' if e['kev'] else ''}"
                 f"Affects {e['exposure']['asset_count']} asset(s), "
                 f"{e['exposure']['internet_facing']} internet-facing."),
        steps=[e["fix"]] + ([f"Also review related: {', '.join(e['related_cves'])}"]
                            if e["related_cves"] else []),
        citations=citations)
    return llm_structured(REMEDIATE_SYS, user, RemediationBrief, demo)

def n_remediate(state: AgentState) -> dict:
    briefs = []
    for e in state["prioritized"]:
        b = synth_brief(e).model_dump()
        b["risk_score"] = e["risk_score"]
        b["exposure"] = e["exposure"]
        briefs.append(b)
        audit("remediate.brief", e["cve"], {"decision": b["decision"], "cites": b["citations"]})
    print(f"[remediate] synthesized {len(briefs)} cited remediation briefs")
    return {"briefs": briefs}
'''))

cells.append(code(r'''
def n_approval(state: AgentState) -> dict:
    act = [b for b in state["briefs"] if b["decision"] == "ACT"]
    if not act:
        return {"approved": []}
    decision = interrupt({
        "type": "approve_remediation_tickets",
        "summary": f"{len(act)} ACT-NOW CVEs — open ServiceNow remediation tasks?",
        "items": [{"cve": b["cve"], "risk_score": b["risk_score"],
                   "assets": b["exposure"]["asset_count"]} for b in act],
        "instructions": "resume with {'approved': [cve ids]} or {'approved': 'ALL'}",
    })
    approved = decision.get("approved", []) if isinstance(decision, dict) else []
    if approved == "ALL":
        approved = [b["cve"] for b in act]
    audit("human.approval", "remediation-tickets", {"approved": approved})
    return {"approved": approved}

def snow_create_remediation_task(brief):
    num = "RTASK" + brief["cve"].replace("CVE-", "").replace("-", "")[:8]
    audit("servicenow.create_task", brief["cve"], {"number": num, "priority": brief["decision"]})
    return {"number": num, "cve": brief["cve"]}
    # === REAL API === POST {SNOW}/api/now/table/sc_task (assignment_group=Vuln Mgmt, ...)

def n_tickets(state: AgentState) -> dict:
    by_cve = {b["cve"]: b for b in state["briefs"]}
    tickets = [snow_create_remediation_task(by_cve[c]) for c in state["approved"]]
    print(f"[tickets] opened {len(tickets)} ServiceNow remediation task(s)")
    return {"tickets": tickets}

def n_report(state: AgentState) -> dict:
    counts = {}
    for b in state["briefs"]:
        counts[b["decision"]] = counts.get(b["decision"], 0) + 1
    report = {"cves": len(state["briefs"]), "by_decision": counts,
              "tickets_opened": len(state["tickets"]),
              "top": [b["cve"] for b in state["briefs"][:3]]}
    print(f"[report] {report}")
    return {"report": report}
'''))

cells.append(md('## 7. Build & compile the graph'))

cells.append(code(r'''
g = StateGraph(AgentState)
for name, fn in [("enrich", n_enrich), ("graph", n_graph), ("prioritize", n_prioritize),
                 ("remediate", n_remediate), ("approval", n_approval),
                 ("tickets", n_tickets), ("report", n_report)]:
    g.add_node(name, fn)
g.add_edge(START, "enrich")
g.add_edge("enrich", "graph")
g.add_edge("graph", "prioritize")
g.add_edge("prioritize", "remediate")
g.add_edge("remediate", "approval")
g.add_edge("approval", "tickets")
g.add_edge("tickets", "report")
g.add_edge("report", END)
app = g.compile(checkpointer=MemorySaver())
print("Graph compiled:", list(app.get_graph().nodes))
'''))

cells.append(md(r'''
## 8. Run it — give the agent a list of CVEs

This is the "just give it a CVE or a list" entry point. The agent enriches, graphs,
prioritizes, and drafts remediations, then **pauses** before opening tickets.
'''))

cells.append(code(r'''
AUDIT.clear()
INPUT_CVES = list(NVD)   # or any subset, e.g. ["CVE-2021-44228", "CVE-2023-23397"]
config = {"configurable": {"thread_id": "cve-run-2026-06-02"}}
init = {"input_cves": INPUT_CVES, "enriched": [], "prioritized": [], "briefs": [],
        "approved": [], "tickets": [], "report": {}}
result = app.invoke(init, config)

print("\n=== PAUSED FOR APPROVAL ===")
intr = result["__interrupt__"][0].value
print(intr["summary"])
for it in intr["items"]:
    print(f"  - {it['cve']:16s} score={it['risk_score']:.3f}  assets={it['assets']}")
'''))

cells.append(code(r'''
final = app.invoke(Command(resume={"approved": "ALL"}), config)
print("\n=== REPORT ===")
print(json.dumps(final["report"], indent=2))
'''))

cells.append(md('## 9. Results — prioritized queue + remediation briefs'))

cells.append(code(r'''
rows = [{"rank": i + 1, "cve": b["cve"], "decision": b["decision"],
         "risk": b["risk_score"], "assets": b["exposure"]["asset_count"],
         "inet": b["exposure"]["internet_facing"], "summary": b["summary"]}
        for i, b in enumerate(final["briefs"])]
display(pd.DataFrame(rows))
'''))

cells.append(code(r'''
# Per-CVE remediation briefs (what an analyst actually reads)
for b in final["briefs"]:
    print(f"\n{'='*78}\n[{b['decision']}] {b['cve']}   risk={b['risk_score']}")
    print(b["summary"])
    for i, s in enumerate(b["steps"], 1):
        print(f"  {i}. {s}")
    print("  citations:", ", ".join(b["citations"]))
'''))

cells.append(md(r'''
## 10. Optional — conversational CVE analyst (tool-using ReAct agent)

The graph above is the batch pipeline. For ad-hoc questions ("what's the blast radius of
Heartbleed, and what do we patch first?"), a tool-calling agent is the right shape. The
agent gets the same enrichment + graph + RAG functions as tools. **Requires a live LLM
key.**
'''))

cells.append(code(r'''
from langchain_core.tools import tool

@tool
def tool_enrich(cve: str) -> dict:
    """NVD + KEV + EPSS + asset-exposure facts for a CVE."""
    rec = nvd_lookup(cve)
    if not rec:
        return {"error": "unknown CVE"}
    return {"cvss": rec["cvss_base"], "cwe": rec["cwe"], "products": rec["products"],
            "kev": kev_check(cve), "epss": epss_score(cve),
            "exposure": asset_exposure(rec["products"])}

@tool
def tool_blast_radius(cve: str) -> dict:
    """How many of our assets (and internet-facing) a CVE reaches, plus related CVEs."""
    G = build_cve_graph(list(NVD))
    return {"blast_radius": blast_radius(G, cve), "related": related_cves(G, cve)}

@tool
def tool_remediation(query: str) -> str:
    """Retrieve cited remediation advisory text for a vulnerability query."""
    return format_context(VS.search(query, k=3))

if LLM_AVAILABLE:
    from langgraph.prebuilt import create_react_agent
    analyst = create_react_agent(LLM, tools=[tool_enrich, tool_blast_radius, tool_remediation])
    q = ("I have CVE-2014-0160 and CVE-2019-0708. Which is more urgent for us and why, "
         "and what's the first remediation step for each?")
    out = analyst.invoke({"messages": [HumanMessage(content=q)]})
    print(out["messages"][-1].content)
else:
    print("Skipped: set an LLM key in .env to run the ReAct CVE analyst.")
'''))

cells.append(md(r'''
## 11. Enhancements over the `JH_AI_P4` approach — and what to adopt

The reference is an excellent **RAG/GraphRAG-for-prose** system. CVEs differ on four axes,
and each suggests a concrete upgrade:

1. **Structure-first ingest.** The reference extracts a graph from prose with
   `LLMGraphTransformer`. CVE core data (CVSS, CWE, CPE) is *already structured* in NVD —
   ingest it **deterministically** (zero extraction error, near-zero cost) and reserve the
   LLM for the unstructured advisory text only. *(Implemented in `build_cve_graph`.)*
2. **GraphRAG earns its keep here.** In the reference, hybrid/graph retrieval didn't beat
   tuned dense RAG on prose (their §6.7 diagnostic). For CVEs the relationships are
   *first-class and authoritative* — `AFFECTS`, `INSTANCE_OF`, `REMEDIATED_BY` — so graph
   traversal answers questions dense RAG can't: **blast radius** and **related-CVE / patch
   chaining**. *(Implemented in `blast_radius`, `related_cves`.)*
3. **Decision objective, not answer quality.** Swap RAGAS answer-quality for a
   **prioritization** objective: a transparent SSVC-style score over CVSS + **EPSS**
   (exploit probability) + **KEV** (actively exploited) + **your** exposure. A good
   paragraph isn't the goal; the *right ranking* is. *(Implemented in `risk_score`,
   `ssvc_decision`.)*
4. **Asset-context grounding.** Join CVEs to the **CMDB** so "critical" means critical *to
   you*. The same CVE is an emergency on 10 internet-facing hosts and a backlog item where
   you don't run the product at all. *(Implemented via `INVENTORY` / `asset_exposure`.)*
5. **Live, tool-augmented signals.** Energy reports are static; vuln exploitation changes
   daily. The agent pulls **fresh** KEV/EPSS/NVD at query time rather than relying on a
   frozen corpus. *(Stubbed at each `# === REAL API ===`.)*
6. **Hybrid retrieval that actually helps.** The reference found pure hybrid underwhelming
   on prose. For CVEs, a **structured pre-filter** (by CPE / CVSS band / publish date)
   *before* dense search is a real win — it scopes retrieval to relevant advisories.
   *(Implemented via the `where=` filter in `VS.search`.)*

**Carry over unchanged from the reference** (high-value, drop-in):
- **Citations on every claim** (their §6.10 citation verifier) — a remediation you can't
  trace to NVD/vendor/CISA is not actionable. We tag and surface `[source]` on each brief.
- **Cross-encoder reranking + contextual retrieval** (their §6.12) — switch on when the
  advisory corpus grows and near-duplicates appear.
- **Chain-of-Verification** (their §6.9) — a cheap second pass that checks each remediation
  step is supported by an authoritative source before a ticket is opened.

## 12. Productionizing
- **Real feeds:** NVD 2.0 API (with `NVD_API_KEY`), CISA KEV JSON, FIRST EPSS API, GHSA for
  library ecosystems (map GHSA↔CVE aliases). Cache + schedule a **daily re-score** so KEV/EPSS
  changes re-rank the queue automatically.
- **Persistent GraphRAG:** swap the in-memory `networkx` graph for **Neo4j** (the reference's
  backend) using deterministic `MERGE` from NVD JSON; keep `Neo4jVector` for advisory text.
- **Vector store:** move from the demo NumPy store to **Chroma + `bge`** embeddings (reference
  parity) once the corpus is large; add the cross-encoder reranker.
- **Close the loop:** push ACT items to ServiceNow Vuln Response, then read patch-deployment
  status back to verify remediation — measured by reduction in KEV-exposed, internet-facing
  assets.
'''))

build(OUT, cells, "Problem 3 — CVE Prioritization & Remediation Agent (RAG + GraphRAG)")
validate_code_syntax(OUT)
