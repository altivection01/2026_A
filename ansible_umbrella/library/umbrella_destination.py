#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Ansible module: manage a Cisco Umbrella destination-list entry (allow/deny).

This is the "connector" for the simplified Umbrella allow/deny workflow: you author
a plain YAML list of entries (vars/allowdeny.yml) and the playbook loops them through
this module, which handles auth, the block-vs-allow list, idempotency, the guardrails,
and verification. Safe by default: pass mock=true to simulate with no credentials.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: umbrella_destination
short_description: Manage a Cisco Umbrella destination-list entry (blacklist/whitelist)
description:
  - "Ensures a domain, URL, or IPv4 is present (or absent) in a Cisco Umbrella block or allow Destination List."
  - "Guardrails are enforced in code. A deny on critical infrastructure is refused; an IP block or a URL allow is escalated because Umbrella cannot express it at the DNS layer."
options:
  api_base:
    description: "Umbrella API base URL."
    type: str
    default: "https://api.umbrella.com"
  api_key:
    description: "Umbrella API key (Admin to API Keys, scope Policies). Required unless mock."
    type: str
  api_secret:
    description: "Umbrella API key secret. Required unless mock."
    type: str
  block_list_id:
    description: "Destination List id to use for deny. Auto-discovers the global block list if omitted."
    type: int
  allow_list_id:
    description: "Destination List id to use for allow. Auto-discovers the global allow list if omitted."
    type: int
  destination:
    description: "The domain, URL, or IPv4 to manage."
    type: str
    required: true
  action:
    description: "deny adds to a block list; allow adds to an allow list."
    type: str
    required: true
    choices: [allow, deny]
  comment:
    description: "Comment stored with the destination."
    type: str
    default: ""
  state:
    description: "present adds the entry; absent removes it."
    type: str
    default: present
    choices: [present, absent]
  critical_never_block:
    description: "Registrable domains that must never be blocked."
    type: list
    elements: str
  mock:
    description: "Simulate against an in-memory store (no credentials or network)."
    type: bool
    default: false
author:
  - "2026_A onsite"
"""

EXAMPLES = r"""
- name: Blacklist a C2 domain
  umbrella_destination:
    destination: malware-c2.example
    action: deny
    comment: "Confirmed C2 (INC0456)"
    api_key: "{{ umbrella_api_key }}"
    api_secret: "{{ umbrella_api_secret }}"

- name: Dry-run everything with no credentials
  umbrella_destination:
    destination: bad.example
    action: deny
    mock: true
"""

RETURN = r"""
status: {description: enforced | exists | removed | absent | refused | escalated | would-enforce | would-remove, returned: always, type: str}
reason: {description: Human-readable explanation., returned: always, type: str}
dest_type: {description: domain | url | ipv4 (auto-detected)., returned: always, type: str}
list_id: {description: Destination list id used (when applicable)., returned: when enforced, type: int}
"""

import json
import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError

DEFAULT_CRITICAL = [
    "microsoft.com", "windowsupdate.com", "office.com", "office365.com",
    "login.microsoftonline.com", "azure.com", "contoso.com", "okta.com",
    "google.com", "apple.com", "amazonaws.com", "cisco.com",
]
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
STATE_FILE = os.path.join(tempfile.gettempdir(), "umbrella_ansible_mock.json")


def classify(dest):
    if IPV4.match(dest):
        return "ipv4"
    if "://" in dest or "/" in dest:
        return "url"
    return "domain"


def host_of(dest, dtype):
    if dtype == "url":
        from ansible.module_utils.six.moves.urllib.parse import urlparse
        return urlparse(dest if "://" in dest else "http://" + dest).hostname or dest
    return dest


def registrable(domain):
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _load():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (IOError, ValueError):
        return {}


def _save(s):
    with open(STATE_FILE, "w") as f:
        json.dump(s, f)


# ---- live Umbrella REST helpers (use ansible's dependency-free open_url) ----
def _json(resp):
    return json.loads(resp.read().decode("utf-8"))


def umbrella_token(base, key, secret):
    resp = open_url(base + "/auth/v2/token", method="POST",
                    url_username=key, url_password=secret, force_basic_auth=True)
    return _json(resp)["access_token"]


def umbrella_lists(base, token):
    resp = open_url(base + "/policies/v2/destinationlists",
                    headers={"Authorization": "Bearer " + token})
    return _json(resp)["data"]


def umbrella_destinations(base, token, list_id):
    resp = open_url("%s/policies/v2/destinationlists/%s/destinations" % (base, list_id),
                    headers={"Authorization": "Bearer " + token})
    return _json(resp)["data"]


def umbrella_add(base, token, list_id, destination, comment):
    open_url("%s/policies/v2/destinationlists/%s/destinations" % (base, list_id),
             method="POST",
             headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
             data=json.dumps([{"destination": destination, "comment": comment}]))


def umbrella_remove(base, token, list_id, dest_ids):
    open_url("%s/policies/v2/destinationlists/%s/destinations/remove" % (base, list_id),
             method="DELETE",
             headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
             data=json.dumps(dest_ids))


def run():
    module = AnsibleModule(
        argument_spec=dict(
            api_base=dict(type="str", default="https://api.umbrella.com"),
            api_key=dict(type="str", no_log=True),
            api_secret=dict(type="str", no_log=True),
            block_list_id=dict(type="int"),
            allow_list_id=dict(type="int"),
            destination=dict(type="str", required=True),
            action=dict(type="str", required=True, choices=["allow", "deny"]),
            comment=dict(type="str", default=""),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            critical_never_block=dict(type="list", elements="str", default=DEFAULT_CRITICAL),
            mock=dict(type="bool", default=False),
        ),
        required_if=[["mock", False, ["api_key", "api_secret"]]],
        supports_check_mode=True,
    )
    p = module.params
    dest, action, state = p["destination"].strip(), p["action"], p["state"]
    dtype = classify(dest)
    host = host_of(dest, dtype)
    crit = set(p["critical_never_block"])
    base = dict(destination=dest, action=action, dest_type=dtype)

    # ---- guardrails (code-enforced; independent of any caller) ----
    if action == "deny" and dtype in ("domain", "url") and (
            host in crit or registrable(host) in crit):
        module.exit_json(changed=False, status="refused",
                         reason="%s is critical infrastructure — blocking is prohibited" % host, **base)
    if action == "deny" and dtype == "ipv4":
        module.exit_json(changed=False, status="escalated",
                         reason="Umbrella cannot block a bare IP (IPv4 is allow-only) — route to the firewall/NGFW", **base)
    if action == "allow" and dtype == "url":
        module.exit_json(changed=False, status="escalated",
                         reason="a URL allow cannot be expressed at the DNS layer — submit the domain instead", **base)

    access = "block" if action == "deny" else "allow"

    # ---- mock backend (no creds / network); state persisted to a temp file ----
    if p["mock"]:
        list_id = 11111 if access == "block" else 22222
        s = _load()
        bucket = s.setdefault(str(list_id), {})
        present = dest in bucket
        if state == "present":
            if present:
                module.exit_json(changed=False, status="exists",
                                 reason="already in the %s list" % access, list_id=list_id, **base)
            if module.check_mode:
                module.exit_json(changed=True, status="would-enforce",
                                 reason="would add to the %s list" % access, list_id=list_id, **base)
            bucket[dest] = {"comment": p["comment"]}
            _save(s)
            module.exit_json(changed=True, status="enforced",
                             reason="added to the %s list" % access, list_id=list_id, **base)
        else:
            if not present:
                module.exit_json(changed=False, status="absent", reason="not present", list_id=list_id, **base)
            if module.check_mode:
                module.exit_json(changed=True, status="would-remove", reason="would remove", list_id=list_id, **base)
            del bucket[dest]
            _save(s)
            module.exit_json(changed=True, status="removed", reason="removed from the %s list" % access, list_id=list_id, **base)

    # ---- live backend (Cisco Umbrella REST API) ----
    try:
        token = umbrella_token(p["api_base"], p["api_key"], p["api_secret"])
        list_id = p["block_list_id"] if access == "block" else p["allow_list_id"]
        if not list_id:
            lists = umbrella_lists(p["api_base"], token)
            list_id = next(l["id"] for l in lists if l["access"] == access and l.get("isGlobal"))
        existing = umbrella_destinations(p["api_base"], token, list_id)
        match = [d for d in existing if d.get("destination") == dest]
        if state == "present":
            if match:
                module.exit_json(changed=False, status="exists",
                                 reason="already in list %s" % list_id, list_id=list_id, **base)
            if module.check_mode:
                module.exit_json(changed=True, status="would-enforce", reason="would add to list %s" % list_id, list_id=list_id, **base)
            umbrella_add(p["api_base"], token, list_id, dest, p["comment"])
            verified = any(d.get("destination") == dest
                           for d in umbrella_destinations(p["api_base"], token, list_id))
            module.exit_json(changed=True, status="enforced" if verified else "unverified",
                             reason="added to list %s" % list_id, list_id=list_id, **base)
        else:
            if not match:
                module.exit_json(changed=False, status="absent", reason="not present", list_id=list_id, **base)
            if module.check_mode:
                module.exit_json(changed=True, status="would-remove", reason="would remove from list %s" % list_id, list_id=list_id, **base)
            umbrella_remove(p["api_base"], token, list_id, [d["id"] for d in match])
            module.exit_json(changed=True, status="removed", reason="removed from list %s" % list_id, list_id=list_id, **base)
    except (HTTPError, URLError) as e:
        module.fail_json(msg="Umbrella API error: %s" % e, **base)


def main():
    run()


if __name__ == "__main__":
    main()
