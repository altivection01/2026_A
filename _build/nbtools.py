"""Tiny helpers to assemble valid .ipynb files with nbformat.

Convention used by the build_0X.py scripts: cell sources are passed as plain
strings. Code cells use ONLY double-quoted/triple-double-quoted strings inside,
so the builders can wrap each source in single-triple-quotes without clashing.
"""
from __future__ import annotations

import nbformat
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell


def md(source: str):
    return new_markdown_cell(source.strip("\n"))


def code(source: str):
    return new_code_cell(source.strip("\n"))


def build(path: str, cells: list, title: str):
    nb = new_notebook()
    nb["cells"] = cells
    nb["metadata"] = {
        "kernelspec": {
            "display_name": "Python 3 (2026_A .venv)",
            "language": "python",
            "name": "python3",
        },
        "language_info": {"name": "python", "version": "3.11"},
        "title": title,
    }
    with open(path, "w") as f:
        nbformat.write(nb, f)
    # round-trip validate
    nbformat.validate(nbformat.read(path, as_version=4))
    n_code = sum(1 for c in cells if c["cell_type"] == "code")
    n_md = sum(1 for c in cells if c["cell_type"] == "markdown")
    print(f"WROTE {path}  ({len(cells)} cells: {n_md} md, {n_code} code)")
    return path


def validate_code_syntax(path: str):
    """ast-parse every code cell; report failures. Skips cells with magics."""
    import ast

    nb = nbformat.read(path, as_version=4)
    bad = []
    for i, c in enumerate(nb["cells"]):
        if c["cell_type"] != "code":
            continue
        src = c["source"]
        # strip jupyter line magics / shell escapes so ast.parse is happy
        lines = [
            ("" if (ln.lstrip().startswith("%") or ln.lstrip().startswith("!")) else ln)
            for ln in src.splitlines()
        ]
        clean = "\n".join(lines)
        try:
            ast.parse(clean)
        except SyntaxError as e:
            bad.append((i, e))
    if bad:
        for i, e in bad:
            print(f"  SYNTAX ERROR in code cell {i}: {e}")
        raise SystemExit(f"{path}: {len(bad)} cell(s) failed to parse")
    print(f"  syntax OK — all code cells parse ({path})")
