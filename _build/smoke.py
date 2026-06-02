"""Execute a notebook's code cells as a flat script (offline smoke test).

Run with the test venv python that has a WORKING langgraph:
    /tmp/lgtest/bin/python _build/smoke.py path/to/notebook.ipynb
"""
import json, sys, io, contextlib

path = sys.argv[1]
nb = json.load(open(path))

parts = []
for c in nb["cells"]:
    if c["cell_type"] != "code":
        continue
    src = c["source"]
    if isinstance(src, str):
        src = src.splitlines(keepends=True)
    for ln in src:
        if ln.lstrip().startswith(("%", "!")):
            parts.append("# (magic stripped) " + ln)
        else:
            parts.append(ln)
    parts.append("\n\n")
flat = "".join(parts)

# Jupyter builtins the cells assume:
ns = {"display": lambda *a, **k: [print(repr(x)[:2000]) for x in a], "__name__": "__main__"}

try:
    exec(compile(flat, path, "exec"), ns)
    print("\n=== SMOKE OK:", path, "===")
except Exception:
    import traceback
    print("\n=== SMOKE FAILED:", path, "===")
    traceback.print_exc()
    sys.exit(1)
