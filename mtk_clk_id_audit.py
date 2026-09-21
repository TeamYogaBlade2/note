#!/usr/bin/env python3
"""
Audit MediaTek CCF clock-ID vs clk_hw_onecell_data slot layout.

Designed for a Linux source tree.  It focuses on drivers using the common MediaTek descriptor probe helpers
(mtk_clk_simple_probe / mtk_clk_pdev_probe and their remove helpers).
Custom probe implementations are intentionally out of scope and should be reviewed manually.

What it checks per mtk_clk_desc provider:
  * duplicate clock IDs
  * highest ID >= allocated slot count (definite out-of-bounds)
  * missing ID 0 while positive IDs are present
  * holes inside the registered ID range (reported as candidates; some are intentional)
  * descriptor array/count inconsistencies
  * unresolved ID expressions (reported for manual review)
  * *_NR clock-count definitions in included MediaTek dt-bindings headers

It intentionally errs on the side of reporting candidates rather than
silently declaring complex C macro constructs safe.

Usage:
    ./mtk_clk_id_audit.py /path/to/linux
    ./mtk_clk_id_audit.py /path/to/linux --json out.json
    ./mtk_clk_id_audit.py /path/to/linux --all-ids
    ./mtk_clk_id_audit.py /path/to/linux -q
"""

from __future__ import annotations

import argparse
import ast
import collections
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

# The common helper currently allocates the sum of these descriptor counts.
DESC_FIELDS = (
    "clks",
    "composite_clks",
    "fixed_clks",
    "factor_clks",
    "mux_clks",
    "divider_clks",
    "cpumuxes",
    "plls",
)


@dataclass
class Entry:
    array: str
    expr: str
    line: int
    kind: str
    value: int | None = None


@dataclass
class ArrayInfo:
    name: str
    line: int
    text: str
    entries: list[Entry] = field(default_factory=list)
    recognized: bool = True


@dataclass
class Provider:
    file: str
    desc: str
    line: int
    arrays: dict[str, str] = field(default_factory=dict)  # field -> array
    declared_counts: dict[str, str] = field(default_factory=dict)
    allocated_slots: int | None = None
    ids: list[Entry] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    binding_headers: list[str] = field(default_factory=list)
    nr_defs: dict[str, int] = field(default_factory=dict)


def strip_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"//.*", "", s)
    return s


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def extract_balanced(text: str, open_pos: int) -> tuple[str, int] | None:
    if open_pos >= len(text) or text[open_pos] != "{":
        return None
    depth = 0
    in_str = False
    esc = False
    i = open_pos
    while i < len(text):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[open_pos + 1 : i], i + 1
        i += 1
    return None


def split_top_level_entries(body: str) -> list[tuple[str, int]]:
    """Split a C initializer body on top-level commas."""
    result: list[tuple[str, int]] = []
    start = 0
    par = br = sq = 0
    in_str = False
    esc = False
    for i, c in enumerate(body):
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
            continue
        if c == "(": par += 1
        elif c == ")": par -= 1
        elif c == "{": br += 1
        elif c == "}": br -= 1
        elif c == "[": sq += 1
        elif c == "]": sq -= 1
        elif c == "," and par == br == sq == 0:
            piece = body[start:i].strip()
            if piece:
                result.append((piece, start))
            start = i + 1
    piece = body[start:].strip()
    if piece:
        result.append((piece, start))
    return result


def parse_arrays(text: str) -> dict[str, ArrayInfo]:
    clean = strip_comments(text)
    arrays: dict[str, ArrayInfo] = {}
    pat = re.compile(
        rf"(?:static\s+)?(?:const\s+)?struct\s+{IDENT}\s+({IDENT})\s*\[\s*\]\s*(?:__\w+\s*)*=\s*\{{"
    )
    for m in pat.finditer(clean):
        name = m.group(1)
        bal = extract_balanced(clean, clean.find("{", m.start()))
        if not bal:
            continue
        body, _ = bal
        info = ArrayInfo(name=name, line=line_of(clean, m.start()), text=body)
        for item, rel in split_top_level_entries(body):
            item_clean = item.strip()
            if not item_clean:
                continue
            # Direct struct initializer: .id = CLK_FOO
            dm = re.search(r"\.id\s*=\s*([^,}\n]+)", item_clean)
            if dm:
                expr = dm.group(1).strip()
                line = info.line + body.count("\n", 0, rel)
                info.entries.append(Entry(name, expr, line, "direct"))
                continue
            # Function-like macro initializer: MACRO(CLK_FOO, ...)
            mm = re.match(rf"{IDENT}\s*\(\s*([^,\)]+)", item_clean)
            if mm:
                expr = mm.group(1).strip()
                line = info.line + body.count("\n", 0, rel)
                info.entries.append(Entry(name, expr, line, "macro"))
                continue
            # Some arrays use a macro wrapped in another macro with unusual
            # formatting.  Keep an explicit uncertainty marker.
            if item_clean not in ("{", "}"):
                info.recognized = False
        arrays[name] = info
    return arrays


def parse_descs(text: str) -> list[tuple[str, int, str]]:
    clean = strip_comments(text)
    result = []
    pat = re.compile(rf"static\s+const\s+struct\s+mtk_clk_desc\s+({IDENT})\s*=\s*\{{")
    for m in pat.finditer(clean):
        bal = extract_balanced(clean, clean.find("{", m.start()))
        if bal:
            body, end = bal
            result.append((m.group(1), line_of(clean, m.start()), body))
    return result


def include_bindings(text: str) -> list[str]:
    return re.findall(r"#include\s*[<\"](dt-bindings/clock/[^>\"]+)[>\"]", text)


def eval_simple_expr(expr: str, macros: dict[str, int]) -> int | None:
    expr = expr.strip()
    # Strip C integer suffixes, but only from numeric literals.  Do not
    # touch identifiers that happen to end in a digit followed by U/L (e.g.
    # CLK_INFRA_M4U or CLK_FOO_2L).
    if re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]+", expr):
        expr = re.sub(r"[uUlL]+$", "", expr)
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", expr):
        return int(expr, 0)
    if expr in macros:
        return macros[expr]
    # Resolve a small subset of arithmetic used in bindings.
    if not re.fullmatch(r"[A-Za-z_0-9xXa-fF()+\-*/%<>&|^~ ]+", expr):
        return None
    cur = expr
    for _ in range(32):
        names = set(re.findall(rf"\b{IDENT}\b", cur))
        unresolved = [n for n in names if n not in macros]
        if unresolved:
            return None
        changed = False
        for n in sorted(names, key=len, reverse=True):
            cur2 = re.sub(rf"\b{re.escape(n)}\b", str(macros[n]), cur)
            changed |= cur2 != cur
            cur = cur2
        if not changed:
            break
    try:
        node = ast.parse(cur, mode="eval")
        allowed = (
            ast.Expression, ast.Constant, ast.UnaryOp, ast.BinOp,
            ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
            ast.LShift, ast.RShift, ast.BitOr, ast.BitAnd, ast.BitXor,
            ast.USub, ast.UAdd, ast.Invert, ast.Pow,
        )
        if any(not isinstance(n, allowed) for n in ast.walk(node)):
            return None
        return int(eval(compile(node, "<expr>", "eval"), {"__builtins__": {}}, {}))
    except Exception:
        return None


def parse_binding_file(path: Path) -> tuple[dict[str, int], list[tuple[str, int, str]]]:
    text = path.read_text(errors="replace")
    macros: dict[str, int] = {}
    for name, expr in re.findall(rf"^\s*#define\s+({IDENT})\s+([^/\n]+)", text, flags=re.M):
        v = eval_simple_expr(expr.strip(), macros)
        if v is not None:
            macros[name] = v
    # A lightweight enum parser for the uncommon binding that uses enum {...}.
    enums: list[tuple[str, int, str]] = []
    for em in re.finditer(r"\benum\s*\{([^}]*)\}", text, flags=re.S):
        current = -1
        for item in split_top_level_entries(em.group(1)):
            raw = item[0]
            if "=" in raw:
                n, e = raw.split("=", 1)
                n = n.strip()
                v = eval_simple_expr(e.strip(), macros)
                if v is None:
                    continue
                current = v
            else:
                n = raw.strip()
                current += 1
            if re.fullmatch(IDENT, n):
                macros[n] = current
    # Resolve aliases after all direct definitions are in place.
    for _ in range(8):
        changed = False
        text_lines = text.splitlines()
        for line in text_lines:
            m = re.match(rf"\s*#define\s+({IDENT})\s+([^/\n]+)", line)
            if not m:
                continue
            n, e = m.group(1), m.group(2).strip()
            v = eval_simple_expr(e, macros)
            if v is not None and macros.get(n) != v:
                macros[n] = v
                changed = True
        if not changed:
            break
    return macros, enums


def binding_includes(path: Path) -> list[str]:
    text = path.read_text(errors="replace")
    return re.findall(r"#include\s*[<\"](dt-bindings/clock/[^>\"]+)[>\"]", text)


def resolve_bindings(repo: Path, rels: list[str]) -> tuple[dict[str, int], list[str]]:
    """Resolve binding macros including transitive dt-bindings/clock includes."""
    macros: dict[str, int] = {"CLK_DUMMY": 0}
    used: list[str] = []
    visiting: set[Path] = set()
    done: set[Path] = set()

    def visit(rel: str) -> None:
        p = repo / "include" / rel
        if not p.is_file():
            marker = rel + " (NOT FOUND)"
            if marker not in used:
                used.append(marker)
            return
        if p in done:
            return
        if p in visiting:
            return
        visiting.add(p)
        for child in binding_includes(p):
            visit(child)

        text = p.read_text(errors="replace")
        m, _ = parse_binding_file(p)
        # The current header overrides names inherited from included headers,
        # matching normal preprocessor semantics.
        macros.update(m)
        used.append(str(p.relative_to(repo)))
        visiting.remove(p)
        done.add(p)

    for rel in rels:
        visit(rel)

    # A final pass resolves aliases that refer to macros declared in a
    # transitive include or later in the same header.
    all_binding_paths = [repo / item for item in used if not item.endswith(" (NOT FOUND)")]
    for _ in range(16):
        changed = False
        for p in all_binding_paths:
            text = p.read_text(errors="replace")
            for name, expr in re.findall(rf"^\s*#define\s+({IDENT})\s+([^/\n]+)", text, flags=re.M):
                value = eval_simple_expr(expr.strip(), macros)
                if value is not None and macros.get(name) != value:
                    macros[name] = value
                    changed = True
        if not changed:
            break

    return macros, used


def descriptor_data(body: str) -> tuple[dict[str, str], dict[str, str]]:
    arrays: dict[str, str] = {}
    counts: dict[str, str] = {}
    # C designated initializers do not require a trailing comma on the last
    # member. Accept both `field = value,` and `field = value` before `}`.
    for m in re.finditer(rf"\.({IDENT})\s*=\s*({IDENT})\s*(?=,|\Z)", body):
        field, value = m.groups()
        if field in DESC_FIELDS:
            arrays[field] = value
    for m in re.finditer(rf"\.({IDENT})\s*=\s*([^,]+?)\s*(?=,|\Z)", body):
        field, value = m.groups()
        if field.startswith("num_") and field[4:] in DESC_FIELDS:
            counts[field] = value.strip()
    return arrays, counts


def simple_probe_present(text: str) -> bool:
    clean = strip_comments(text)
    return bool(re.search(
        r"\.probe\s*=\s*(?:mtk_clk_simple_probe|mtk_clk_pdev_probe)\b",
        clean,
    ))


def collect_providers(repo: Path, only_file: str | None = None) -> list[Provider]:
    root = repo / "drivers/clk/mediatek"
    files = [Path(only_file)] if only_file else sorted(root.glob("*.c"))
    providers: list[Provider] = []
    for fp in files:
        if not fp.is_absolute():
            fp = repo / fp
        if not fp.is_file() or "drivers/clk/mediatek" not in str(fp):
            continue
        text = fp.read_text(errors="replace")
        if not simple_probe_present(text):
            continue
        arrays = parse_arrays(text)
        descs = parse_descs(text)
        if not descs:
            continue
        macros, binding_paths = resolve_bindings(repo, include_bindings(text))
        for desc_name, desc_line, body in descs:
            arrmap, counts = descriptor_data(body)
            p = Provider(str(fp.relative_to(repo)), desc_name, desc_line,
                         arrmap, counts, binding_headers=binding_paths)
            total = 0
            for field, arrname in arrmap.items():
                ai = arrays.get(arrname)
                count_expr = counts.get("num_" + field)
                # Field names are e.g. clks -> num_clks.
                if ai is None:
                    p.issues.append(f"descriptor references missing array {arrname} via .{field}")
                    continue
                actual = len(ai.entries)
                if count_expr is not None:
                    count_val = eval_simple_expr(count_expr, {"ARRAY_SIZE_PLACEHOLDER": actual})
                    if count_expr.startswith("ARRAY_SIZE("):
                        declared = actual
                    else:
                        declared = count_val
                    if declared is None:
                        p.issues.append(f"cannot evaluate .num_{field}: {count_expr}")
                    elif declared != actual:
                        p.issues.append(f".num_{field}={declared} but {arrname} has {actual} recognizable entries")
                    total += declared if declared is not None else actual
                else:
                    # A missing count means common probe would treat it as 0.
                    p.issues.append(f"missing .num_{field} for .{field}={arrname}")
                    total += 0
                for e in ai.entries:
                    e.value = eval_simple_expr(e.expr, macros)
                    p.ids.append(e)
                if not ai.recognized:
                    p.issues.append(f"array {arrname} contains an initializer the parser could not classify")
                    p.allocated_slots = None
            if p.allocated_slots is None:
                p.allocated_slots = total
            # Analyze the provider's actual registered IDs.
            values = [e.value for e in p.ids if e.value is not None]
            unresolved = [e for e in p.ids if e.value is None]
            dup = [v for v, c in collections.Counter(values).items() if c > 1]
            if dup:
                p.issues.append("duplicate IDs: " + ", ".join(map(str, sorted(dup))))
            if values:
                lo, hi = min(values), max(values)
                if hi >= p.allocated_slots:
                    p.issues.append(f"OUT-OF-BOUNDS: max ID {hi} >= allocated slots {p.allocated_slots}")
                if lo > 0:
                    p.issues.append(f"NO-ID-0: minimum registered ID is {lo}; no slot 0 is populated")
            # Report sparse ID ranges as candidates. Some MediaTek clock
            # namespaces intentionally reserve IDs, so holes are not treated
            # as a definitive failure for the process exit code.
            if values and not unresolved:
                present = set(values)
                holes = sorted(set(range(lo, hi + 1)) - present)
                if holes:
                    p.issues.append("HOLES: missing IDs in registered range: " + ", ".join(map(str, holes)))

            if unresolved:
                p.issues.append("unresolved IDs: " + ", ".join(sorted({e.expr for e in unresolved})))

            # Extract *_NR and *_NR_CLK constants for diagnostics only.
            # The binding count is not itself a proof of a bug: a provider may
            # intentionally register only a subset of a shared namespace.
            p.nr_defs = {
                n: v for n, v in macros.items()
                if n.endswith("_NR") or n.endswith("_NR_CLK")
            }
            groups: set[str] = set()
            for e in p.ids:
                expr = e.expr
                if expr.startswith("CLK_"):
                    parts = expr.split("_")
                    if len(parts) >= 3:
                        groups.add(parts[1])
            relevant: dict[str, int] = {}
            for group in sorted(groups):
                candidates = [
                    (name, value) for name, value in macros.items()
                    if name.startswith("CLK_") and group in name.split("_")
                    and (name.endswith("_NR") or name.endswith("_NR_CLK"))
                ]
                candidates += [
                    (name, value) for name, value in macros.items()
                    if f"_CLK_{group}_NR" in name
                    and (name.endswith("_NR") or name.endswith("_NR_CLK"))
                ]
                for name, value in candidates:
                    relevant[name] = value
            p.nr_defs = relevant
            providers.append(p)
    return providers


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo", type=Path, help="Linux source tree")
    ap.add_argument("--file", help="audit one driver file")
    ap.add_argument("--json", type=Path, help="write machine-readable JSON")
    ap.add_argument("--all-ids", action="store_true", help="print every resolved ID")
    ap.add_argument("-q", "--quit", action="store_true",
                    help="do not print providers with no findings")
    args = ap.parse_args()

    repo = args.repo.resolve()
    if not (repo / "drivers/clk/mediatek/clk-mtk.c").is_file():
        ap.error(f"not a Linux tree (missing {repo/'drivers/clk/mediatek/clk-mtk.c'})")

    providers = collect_providers(repo, args.file)
    bad = [p for p in providers if p.issues]

    print(f"MediaTek CCF descriptor-helper providers: {len(providers)}")
    print(f"Providers with findings:              {len(bad)}")
    print()
    for p in providers:
        status = "FINDINGS" if p.issues else "OK"
        if args.quit and not p.issues:
            continue
        print(f"[{status}] {p.file}:{p.line}  {p.desc}")
        print(f"  arrays: " + ", ".join(f"{f}={a}" for f, a in p.arrays.items()))
        print(f"  allocated slots (descriptor counts): {p.allocated_slots}")
        vals = [(e.value, e.expr, e.array, e.line) for e in p.ids]
        if args.all_ids:
            print("  IDs:")
            for value, expr, arr, line in vals:
                print(f"    {value!s:>4}  {expr:<36} {arr}:{line}")
        if p.nr_defs:
            print("  binding *_NR: " + ", ".join(f"{k}={v}" for k, v in sorted(p.nr_defs.items())))
        for issue in p.issues:
            print(f"  !!! {issue}")
        print()

    if args.json:
        serial = []
        for p in providers:
            d = asdict(p)
            serial.append(d)
        args.json.write_text(json.dumps(serial, indent=2, ensure_ascii=False))
        print(f"JSON: {args.json}")

    # Non-zero only for definite structural findings, not unresolved-only cases.
    definite = [p for p in providers if any(
        s.startswith(("OUT-OF-BOUNDS", "duplicate IDs", "NO-ID-0", ".num_", "missing .num_"))
        for s in p.issues
    )]
    return 1 if definite else 0


if __name__ == "__main__":
    raise SystemExit(main())
