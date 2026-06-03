#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Ansible module: manage an Infoblox NIOS RPZ rule (allow/deny) via the WAPI.

The "connector" for the simplified Infoblox allow/deny workflow: you author a plain
YAML list of entries (vars/allowdeny.yml) and the playbook loops them through this
module, which handles WAPI auth, the block-vs-passthru rule, idempotency (incl.
flipping an existing rule), the guardrails, and removal. Safe by default: pass
mock=true to simulate with no Grid Master.

Two rule families are supported:
  - DOMAIN / URL  -> record:rpz:cname            (QNAME trigger; URLs reduced to domain)
  - IPv4 / CIDR   -> record:rpz:cname:ipaddress  (RPZ-IP trigger on the answer IP)

Rule encoding (both objects):
  - deny  (blacklist) -> canonical = ""        => Block (No Such Domain / NXDOMAIN)
  - allow (whitelist) -> canonical = <name>    => Passthru (allow) rule
RPZ-IP owner names use the reversed-octet form: 192.0.2.0/24 -> 24.0.2.0.192.rpz-ip
(a single IP is /32, e.g. 192.0.2.9 -> 32.9.2.0.192.rpz-ip).
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: infoblox_rpz
short_description: Manage an Infoblox NIOS RPZ rule (blacklist/whitelist) via the WAPI
description:
  - "Ensures a domain, URL, IPv4 address, or IPv4 CIDR block is blocked or allowed in an Infoblox Response Policy Zone."
  - "Domains and URLs use record:rpz:cname (QNAME trigger; URLs are reduced to their domain). IPv4 addresses and CIDR blocks use record:rpz:cname:ipaddress (RPZ-IP trigger on the answer IP)."
  - "Guardrails are enforced in code. A deny on critical infrastructure is refused; an overly broad CIDR (prefix shorter than /8) or a loopback/null address is refused."
options:
  grid_host:
    description: "Grid Master base URL, e.g. https://192.0.2.10. Required unless mock."
    type: str
  wapi_version:
    description: "NIOS WAPI version."
    type: str
    default: "v2.13"
  username:
    description: "NIOS admin username. Required unless mock."
    type: str
  password:
    description: "NIOS admin password. Required unless mock."
    type: str
  validate_certs:
    description: "Validate the Grid Master TLS certificate (often self-signed)."
    type: bool
    default: false
  rp_zone:
    description: "The Response Policy Zone the rule belongs to, e.g. rpz.corp.local. Required unless mock."
    type: str
  destination:
    description: "The domain, URL, IPv4 address, or IPv4 CIDR block to manage."
    type: str
    required: true
  action:
    description: "deny creates a Block (NXDOMAIN) rule; allow creates a Passthru rule."
    type: str
    required: true
    choices: [allow, deny]
  comment:
    description: "Comment stored on the RPZ record."
    type: str
    default: ""
  state:
    description: "present creates/updates the rule; absent removes it."
    type: str
    default: present
    choices: [present, absent]
  critical_never_block:
    description: "Registrable domains that must never be blocked."
    type: list
    elements: str
  mock:
    description: "Simulate against an in-memory store (no Grid Master or network)."
    type: bool
    default: false
author:
  - "2026_A onsite"
"""

EXAMPLES = r"""
- name: Blacklist a C2 domain (Block / NXDOMAIN)
  infoblox_rpz:
    destination: malware-c2.example
    action: deny
    rp_zone: rpz.corp.local
    grid_host: https://192.0.2.10
    username: admin
    password: "{{ infoblox_password }}"

- name: Block a single IP via RPZ-IP (record:rpz:cname:ipaddress)
  infoblox_rpz:
    destination: 203.0.113.66        # -> owner name 32.66.113.0.203.rpz-ip
    action: deny
    rp_zone: rpz.corp.local
    grid_host: https://192.0.2.10
    username: admin
    password: "{{ infoblox_password }}"

- name: Block a whole CIDR via RPZ-IP
  infoblox_rpz:
    destination: 198.51.100.0/24     # -> owner name 24.0.100.51.198.rpz-ip
    action: deny
    rp_zone: rpz.corp.local
    grid_host: https://192.0.2.10
    username: admin
    password: "{{ infoblox_password }}"

- name: Dry-run everything with no Grid Master
  infoblox_rpz:
    destination: bad.example
    action: deny
    mock: true
"""

RETURN = r"""
status: {description: "enforced | updated | exists | removed | absent | refused | would-*", returned: always, type: str}
reason: {description: "Human-readable explanation.", returned: always, type: str}
dest_type: {description: "domain | url | ipv4 (single IP or CIDR).", returned: always, type: str}
rule: {description: "block (NXDOMAIN) or passthru (allow).", returned: when applicable, type: str}
record: {description: "The RPZ record/owner name acted on.", returned: when applicable, type: str}
"""

import json
import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.six.moves.urllib.parse import urlencode, urlparse

DEFAULT_CRITICAL = [
    "microsoft.com", "windowsupdate.com", "office.com", "office365.com",
    "login.microsoftonline.com", "azure.com", "contoso.com", "okta.com",
    "google.com", "apple.com", "amazonaws.com", "infoblox.com",
]
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV4_CIDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
STATE_FILE = os.path.join(tempfile.gettempdir(), "infoblox_ansible_mock.json")


def classify(dest):
    if IPV4.match(dest) or IPV4_CIDR.match(dest):   # check CIDR before the URL '/' test
        return "ipv4"
    if "://" in dest or "/" in dest:
        return "url"
    return "domain"


def domain_of(dest, dtype):
    if dtype == "url":
        return urlparse(dest if "://" in dest else "http://" + dest).hostname or dest
    return dest


def registrable(domain):
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def rpz_ip_name(ipcidr):
    """Encode an IPv4 address/CIDR as an RPZ-IP owner name (reversed octets + prefix).
       192.0.2.0/24 -> 24.0.2.0.192.rpz-ip ; 192.0.2.9 -> 32.9.2.0.192.rpz-ip"""
    addr, _, prefix = ipcidr.partition("/")
    prefix = prefix or "32"
    return ".".join([prefix] + addr.split(".")[::-1]) + ".rpz-ip"


def ip_guardrail(ipcidr):
    """Return a refusal reason for dangerous IP rules, else None."""
    addr, _, prefix = ipcidr.partition("/")
    try:
        plen = int(prefix) if prefix else 32
    except ValueError:
        return "invalid CIDR prefix in %s" % ipcidr
    if plen < 8 or plen > 32:
        return "refusing an out-of-range/overly broad prefix (/%s) in %s" % (plen, ipcidr)
    if addr.startswith("127.") or addr == "0.0.0.0":
        return "refusing to block loopback/null address %s" % addr
    return None


def _load():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (IOError, ValueError):
        return {}


def _save(s):
    with open(STATE_FILE, "w") as f:
        json.dump(s, f)


# ---- live NIOS WAPI helper (HTTP Basic; open_url is dependency-free) ----
def _wapi(p, path, method="GET", data=None):
    url = "%s/wapi/%s/%s" % (p["grid_host"].rstrip("/"), p["wapi_version"], path)
    resp = open_url(url, method=method,
                    url_username=p["username"], url_password=p["password"],
                    force_basic_auth=True, validate_certs=p["validate_certs"],
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(data) if data is not None else None)
    body = resp.read().decode("utf-8")
    return json.loads(body) if body else None


def run():
    module = AnsibleModule(
        argument_spec=dict(
            grid_host=dict(type="str"),
            wapi_version=dict(type="str", default="v2.13"),
            username=dict(type="str"),
            password=dict(type="str", no_log=True),
            validate_certs=dict(type="bool", default=False),
            rp_zone=dict(type="str"),
            destination=dict(type="str", required=True),
            action=dict(type="str", required=True, choices=["allow", "deny"]),
            comment=dict(type="str", default=""),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            critical_never_block=dict(type="list", elements="str", default=DEFAULT_CRITICAL),
            mock=dict(type="bool", default=False),
        ),
        required_if=[["mock", False, ["grid_host", "username", "password", "rp_zone"]]],
        supports_check_mode=True,
    )
    p = module.params
    dest, action, state = p["destination"].strip(), p["action"], p["state"]
    dtype = classify(dest)
    crit = set(p["critical_never_block"])
    base = dict(destination=dest, dest_type=dtype)

    # ---- guardrails ----
    if action == "deny" and dtype in ("domain", "url"):
        domain = domain_of(dest, dtype)
        if domain in crit or registrable(domain) in crit:
            module.exit_json(changed=False, status="refused",
                             reason="%s is critical infrastructure — blocking is prohibited" % domain, **base)
    if dtype == "ipv4":
        g = ip_guardrail(dest)
        if g:
            module.exit_json(changed=False, status="refused", reason=g, **base)

    # ---- object + owner name + desired canonical ----
    if dtype == "ipv4":
        obj_type = "record:rpz:cname:ipaddress"
        rec_name = rpz_ip_name(dest)
        label = "RPZ-IP"
    else:
        obj_type = "record:rpz:cname"
        rec_name = domain_of(dest, dtype)
        label = "RPZ"
    rule = "passthru" if action == "allow" else "block"
    desired_canonical = rec_name if rule == "passthru" else ""   # "" => NXDOMAIN block
    zone = p["rp_zone"] or "rpz.corp.local"
    base["rule"] = rule
    base["record"] = "%s (%s)" % (rec_name, zone)
    set_msg = "%s %s rule set" % (label, rule)

    # ---- mock backend (no Grid Master); state persisted to a temp file ----
    if p["mock"]:
        s = _load()
        bucket = s.setdefault(zone, {})
        cur = bucket.get(rec_name)              # stored canonical or None
        if state == "present":
            if cur is not None and cur == desired_canonical:
                module.exit_json(changed=False, status="exists",
                                 reason="%s %s rule already present" % (label, rule), **base)
            if module.check_mode:
                module.exit_json(changed=True,
                                 status="would-update" if cur is not None else "would-enforce",
                                 reason="would set " + set_msg, **base)
            bucket[rec_name] = desired_canonical
            _save(s)
            module.exit_json(changed=True,
                             status="updated" if cur is not None else "enforced",
                             reason=set_msg, **base)
        else:
            if cur is None:
                module.exit_json(changed=False, status="absent", reason="no %s rule present" % label, **base)
            if module.check_mode:
                module.exit_json(changed=True, status="would-remove", reason="would remove %s rule" % label, **base)
            del bucket[rec_name]
            _save(s)
            module.exit_json(changed=True, status="removed", reason="%s rule removed" % label, **base)

    # ---- live backend (NIOS WAPI) ----
    try:
        q = obj_type + "?" + urlencode({"name": rec_name, "rp_zone": zone,
                                        "_return_fields": "name,canonical,comment"})
        found = _wapi(p, q) or []
        existing = found[0] if found else None
        if state == "present":
            if existing and existing.get("canonical", "") == desired_canonical:
                module.exit_json(changed=False, status="exists",
                                 reason="%s %s rule already present" % (label, rule), **base)
            if module.check_mode:
                module.exit_json(changed=True,
                                 status="would-update" if existing else "would-enforce",
                                 reason="would set " + set_msg, **base)
            if existing:                         # flip the rule (passthru <-> block)
                _wapi(p, existing["_ref"], method="PUT",
                      data={"canonical": desired_canonical, "comment": p["comment"]})
                module.exit_json(changed=True, status="updated", reason="%s rule updated to %s" % (label, rule), **base)
            _wapi(p, obj_type, method="POST",
                  data={"name": rec_name, "canonical": desired_canonical, "rp_zone": zone,
                        "comment": p["comment"]})
            module.exit_json(changed=True, status="enforced", reason="%s %s rule created" % (label, rule), **base)
        else:
            if not existing:
                module.exit_json(changed=False, status="absent", reason="no %s rule present" % label, **base)
            if module.check_mode:
                module.exit_json(changed=True, status="would-remove", reason="would remove %s rule" % label, **base)
            _wapi(p, existing["_ref"], method="DELETE")
            module.exit_json(changed=True, status="removed", reason="%s rule removed" % label, **base)
    except (HTTPError, URLError) as e:
        module.fail_json(msg="Infoblox WAPI error: %s" % e, **base)


def main():
    run()


if __name__ == "__main__":
    main()
