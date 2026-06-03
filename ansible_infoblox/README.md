# Problem 4 — Infoblox allow/deny via Ansible

The Infoblox counterpart to [`../ansible_umbrella`](../ansible_umbrella): **you edit one YAML
file, run one playbook, and it's pushed to Infoblox** — here as **NIOS Response Policy Zone
(RPZ) rules** over the WAPI. A custom Ansible module (the "connector") handles auth, the
block-vs-passthru rule, idempotency, and the safety guardrails, so the YAML you author stays
trivial.

## The process (three steps)

1. **Edit [`vars/allowdeny.yml`](vars/allowdeny.yml)** — one entry per site:
   ```yaml
   allowdeny_entries:
     - { destination: malware-c2.example, action: deny,  comment: "Confirmed C2 (INC0456)" }
     - { destination: partner-portal.com, action: allow, comment: "Approved vendor" }
   ```
   `action: deny` → blacklist (RPZ **Block / NXDOMAIN**), `action: allow` → whitelist (RPZ
   **Passthru**). `destination` can be a domain or full URL (URLs are reduced to their
   domain). Add `state: absent` to remove a rule.

2. **Configure connection once** in [`group_vars/all.yml`](group_vars/all.yml) (vault the
   password): Grid Master URL, WAPI version, admin user/password, and the **RPZ zone** to
   write rules into.
   ```bash
   ansible-vault encrypt_string 'THE_PASSWORD' --name 'infoblox_password'   # paste into all.yml
   ```

3. **Push:**
   ```bash
   ansible-playbook push_infoblox.yml --check     # dry run (live), shows what would change
   ansible-playbook push_infoblox.yml             # apply for real
   ```

No Grid Master handy? Add `-e mock=true` to simulate the whole flow end-to-end (persisted to
a temp state file so re-runs show idempotency):
```bash
ansible-playbook push_infoblox.yml -e mock=true            # simulate apply
ansible-playbook push_infoblox.yml -e mock=true --check    # simulate dry run
```

## How RPZ rules are encoded (`record:rpz:cname`)
| action | canonical | RPZ rule |
|--------|-----------|----------|
| `deny`  | `""` (empty)        | Block — **No Such Domain (NXDOMAIN)** |
| `allow` | `<the domain>`      | **Passthru** (allow / exception) |

## What the connector enforces (so you don't have to)
The `infoblox_rpz` module applies guardrails **in code**, on every entry:
- **Never blocks critical infrastructure** (`microsoft.com`, Windows Update, identity
  providers, etc.) → reported `refused`.
- **Bare IPs are escalated** → RPZ is domain-based; an IP block needs an **RPZ-IP** rule
  (`record:rpz:cname:ipaddress`) or the firewall, which this module deliberately does not
  manage.
- **Idempotent, and it flips rules:** re-running an unchanged entry is `exists` (`changed=0`);
  changing an entry from `allow` to `deny` (or vice-versa) **updates** the existing RPZ record
  in place.
- **`-e strict=true`** fails the run if anything was refused/escalated (use this in CI).

Per-entry status: `enforced` / `updated` / `exists` / `refused` / `escalated` / `removed` /
`would-*`.

## Layout
```
ansible_infoblox/
├── push_infoblox.yml          # the playbook (loop entries -> module -> summary)
├── vars/allowdeny.yml         # <-- the file you edit (key: allowdeny_entries)
├── group_vars/all.yml         # Grid Master connection (password vaulted) + RPZ zone
├── library/
│   └── infoblox_rpz.py        # the connector (custom module): WAPI, idempotency, guardrails
├── inventory.ini              # localhost (WAPI calls run from the control node)
└── ansible.cfg
```

## How this differs from `ansible_umbrella`
Both follow the identical "edit YAML → push" pattern; the differences are the enforcement layer:

| | Umbrella | Infoblox RPZ |
|---|---|---|
| Mechanism | Destination Lists (block/allow) | `record:rpz:cname` (NXDOMAIN block / passthru) |
| Auth | OAuth2 client-credentials | WAPI HTTP Basic to the Grid Master |
| URL | full URL kept (proxy) | reduced to its **domain** (path-blind) |
| Bare IP | allow-list only (deny escalates) | **escalated** (RPZ-IP is a separate object) |
| Vars key | `umbrella_entries` | `allowdeny_entries` |

Run **both** (in their own dirs) to enforce a block/allow across cloud *and* on-prem DNS —
the hybrid posture, now as two simple, independent playbooks.

## Notes
- **No official Infoblox NIOS collection is required** — this wraps the WAPI
  (`record:rpz:cname`) with `ansible.module_utils.urls` (no extra Python deps). The community
  `infoblox.nios_modules` collection exists if you prefer it, but it has no dedicated RPZ-rule
  module, so a thin custom module keeps the YAML clean and idempotent.
- **GitOps:** keep `allowdeny.yml` in version control and run from CI on merge — the file is
  the auditable source of truth for what's blocked/allowed on-prem.
- Requires `ansible-core` on the control node. Verified with `--check`, apply, idempotent
  re-apply, rule-flip update, removal, and `strict` modes.
