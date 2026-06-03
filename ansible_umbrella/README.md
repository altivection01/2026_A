# Problem 4 — Umbrella allow/deny via Ansible

A simplified, GitOps-friendly way to manage Cisco Umbrella block/allow lists: **you edit one
YAML file, run one playbook, and it's pushed to Umbrella.** A custom Ansible module (the
"connector") handles auth, the block-vs-allow list, idempotency, and the safety guardrails,
so the YAML you author stays trivial.

## The process (three steps)

1. **Edit [`vars/allowdeny.yml`](vars/allowdeny.yml)** — one entry per site:
   ```yaml
   umbrella_entries:
     - { destination: malware-c2.example, action: deny,  comment: "Confirmed C2 (INC0456)" }
     - { destination: partner-portal.com, action: allow, comment: "Approved vendor" }
     - { destination: 198.51.100.10,      action: allow, comment: "Partner SFTP IP" }
   ```
   `action: deny` → blacklist, `action: allow` → whitelist. `destination` can be a domain,
   full URL, or IPv4 (type auto-detected). Add `state: absent` to remove an entry.

2. **Configure credentials once** in [`group_vars/all.yml`](group_vars/all.yml) (vault the
   secret): an Umbrella API key/secret with the **Policies** scope. Optionally pin your
   block/allow list IDs; otherwise the connector auto-discovers your global lists.
   ```bash
   ansible-vault encrypt_string 'THE_SECRET' --name 'umbrella_api_secret'   # paste into all.yml
   ```

3. **Push:**
   ```bash
   ansible-playbook push_umbrella.yml --check     # dry run (live), shows what would change
   ansible-playbook push_umbrella.yml             # apply for real
   ```

No credentials yet? Add `-e mock=true` to simulate the whole flow end-to-end (it persists to
a temp state file so re-runs show idempotency):
```bash
ansible-playbook push_umbrella.yml -e mock=true            # simulate apply
ansible-playbook push_umbrella.yml -e mock=true --check    # simulate dry run
```

## What the connector enforces (so you don't have to)
The `umbrella_destination` module applies the same guardrails the notebook agent did —
**in code**, on every entry:
- **Never blocks critical infrastructure** (`microsoft.com`, Windows Update, identity
  providers, etc.) → reported `refused`.
- **IP deny** and **URL allow** aren't expressible in Umbrella DNS → reported `escalated`
  (an IP block belongs on the firewall; a URL allow should be submitted as a domain).
- **Idempotent:** re-running only pushes new/changed entries (`changed=0` on a no-op run).
- **`-e strict=true`** fails the run if anything was refused/escalated (use this in CI).

Per-entry status is printed in the play summary: `enforced` / `exists` / `refused` /
`escalated` / `removed` / `would-enforce`.

## Layout
```
ansible_umbrella/
├── push_umbrella.yml          # the playbook (loop entries -> module -> summary)
├── vars/allowdeny.yml         # <-- the file you edit
├── group_vars/all.yml         # Umbrella creds (vaulted) + options
├── library/
│   └── umbrella_destination.py  # the connector (custom module): auth, idempotency, guardrails
├── inventory.ini              # localhost (API calls run from the control node)
└── ansible.cfg
```

## Notes
- **No official Umbrella Ansible collection exists** — this wraps the Umbrella REST API
  (`/policies/v2/destinationlists`) with `ansible.module_utils.urls` (no extra Python deps).
  A pure `ansible.builtin.uri` playbook is possible too, but the module keeps the YAML clean
  and makes idempotency + guardrails reliable.
- **No native expiry** in Umbrella: put the expiry date in the `comment` and run this
  playbook on a schedule with a "remove past-due" pass (a future enhancement), or manage
  the desired state entirely in `allowdeny.yml` (delete the line + `state: absent`).
- **GitOps:** keep `allowdeny.yml` in version control and run the playbook from CI on merge —
  the file becomes the auditable source of truth for what's blocked/allowed.
- Requires `ansible-core` on the control node (`pip install ansible-core`). Verified against
  ansible-core with `--check`, apply, idempotent re-apply, and `strict` modes.
