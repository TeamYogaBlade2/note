#!/usr/bin/env python3
"""Audit missing MediaTek CCF descriptor clk_lock assignments.

The checker focuses on mtk_clk_desc providers used by mtk_clk_simple_probe()
or mtk_clk_pdev_probe(). It reports descriptors which provide mux_clks or
divider_clks without a non-NULL clk_lock, plus optional-lock composite-only
cases for manual review.

This is a static candidate finder, not a proof that every reported lock is
required: clk_lock is optional at the generic API boundary. Whether it is
needed depends on concurrent read-modify-write access to shared registers.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
LOCK_FIELDS = ("mux_clks", "divider_clks")
OPTIONAL_LOCK_FIELDS = ("composite_clks",)


@dataclass
class Finding:
    file: str
    descriptor: str
    line: int
    severity: str
    lock_fields: list[str] = field(default_factory=list)
    optional_fields: list[str] = field(default_factory=list)
    lock_expression: str | None = None
    spinlocks_in_file: list[str] = field(default_factory=list)
    message: str = ""


def strip_comments(text: str) -> str:
    """Remove C comments while retaining strings and newlines."""
    out: list[str] = []
    i = 0
    in_string = False
    in_char = False
    escaped = False
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if in_string or in_char:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif in_string and c == '"':
                in_string = False
            elif in_char and c == "'":
                in_char = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "'":
            in_char = True
            out.append(c)
            i += 1
            continue
        if c == "/" and n == "*":
            i += 2
            while i + 1 < len(text) and text[i:i + 2] != "*/":
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i = min(len(text), i + 2)
            continue
        if c == "/" and n == "/":
            i += 2
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def extract_braced(text: str, open_pos: int) -> tuple[str, int] | None:
    if open_pos >= len(text) or text[open_pos] != "{":
        return None
    depth = 0
    in_string = False
    in_char = False
    escaped = False
    for i in range(open_pos, len(text)):
        c = text[i]
        if in_string or in_char:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif in_string and c == '"':
                in_string = False
            elif in_char and c == "'":
                in_char = False
            continue
        if c == '"':
            in_string = True
        elif c == "'":
            in_char = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i + 1
    return None


def split_top_level(body: str) -> list[str]:
    """Split a C initializer on commas outside nested expressions."""
    items: list[str] = []
    start = 0
    paren = brace = bracket = 0
    in_string = False
    in_char = False
    escaped = False
    for i, c in enumerate(body):
        if in_string or in_char:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif in_string and c == '"':
                in_string = False
            elif in_char and c == "'":
                in_char = False
            continue
        if c == '"':
            in_string = True
        elif c == "'":
            in_char = True
        elif c == "(":
            paren += 1
        elif c == ")":
            paren -= 1
        elif c == "{":
            brace += 1
        elif c == "}":
            brace -= 1
        elif c == "[":
            bracket += 1
        elif c == "]":
            bracket -= 1
        elif c == "," and paren == brace == bracket == 0:
            item = body[start:i].strip()
            if item:
                items.append(item)
            start = i + 1
    tail = body[start:].strip()
    if tail:
        items.append(tail)
    return items


def parse_designators(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in split_top_level(body):
        m = re.match(rf"\.({IDENT})\s*=\s*(.+)$", item, re.S)
        if m:
            fields[m.group(1)] = m.group(2).strip()
    return fields


def probe_uses_common_helper(text: str) -> bool:
    """Recognize direct helper assignments and thin wrappers around them."""
    clean = strip_comments(text)
    assigned = re.findall(rf"\.probe\s*=\s*({IDENT})\b", clean)
    for fn in assigned:
        if fn in ("mtk_clk_simple_probe", "mtk_clk_pdev_probe"):
            return True
        # A few drivers historically wrapped mtk_clk_simple_probe() to add
        # child population or logging. Inspect only the function assigned to
        # .probe rather than accepting any unrelated helper call in the file.
        pat = re.compile(rf"(?:static\s+)?int\s+{re.escape(fn)}\s*\([^;]*?\)\s*\{{", re.S)
        m = pat.search(clean)
        if not m:
            continue
        brace = clean.find("{", m.start())
        body = extract_braced(clean, brace)
        if body and re.search(r"\bmtk_clk_(?:simple|pdev)_probe\s*\(", body[0]):
            return True
    return False


def descriptor_initializers(text: str):
    clean = strip_comments(text)
    pat = re.compile(rf"static\s+const\s+struct\s+mtk_clk_desc\s+({IDENT})\s*=\s*\{{")
    for m in pat.finditer(clean):
        brace = clean.find("{", m.start())
        parsed = extract_braced(clean, brace)
        if not parsed:
            continue
        body, _ = parsed
        yield m.group(1), clean.count("\n", 0, m.start()) + 1, parse_designators(body)


def is_null_expr(expr: str | None) -> bool:
    if expr is None:
        return True
    compact = re.sub(r"\s+", "", expr)
    return compact in {"NULL", "0", "0U", "0UL", "0L", "nullptr"}


def spinlock_names(text: str) -> list[str]:
    clean = strip_comments(text)
    names = set(re.findall(rf"\bDEFINE_SPINLOCK\s*\(\s*({IDENT})\s*\)", clean))
    names.update(re.findall(rf"\bspinlock_t\s+({IDENT})\b", clean))
    names.update(re.findall(rf"\b__SPIN_LOCK_UNLOCKED\s*\(\s*({IDENT})\s*\)", clean))
    return sorted(names)


def audit_file(repo: Path, path: Path, include_optional: bool) -> list[Finding]:
    raw = path.read_text(errors="replace")
    clean = strip_comments(raw)
    if not probe_uses_common_helper(clean):
        return []

    locks = spinlock_names(clean)
    findings: list[Finding] = []
    for desc, line, fields in descriptor_initializers(clean):
        active: list[str] = []
        for field_name in LOCK_FIELDS + OPTIONAL_LOCK_FIELDS:
            array = fields.get(field_name)
            if array is None or is_null_expr(array):
                continue
            count = fields.get("num_" + field_name)
            if count is not None and re.fullmatch(r"\s*0(?:[uUlL]+)?\s*", count):
                continue
            active.append(field_name)

        if not active:
            continue

        lock_expr = fields.get("clk_lock")
        if not is_null_expr(lock_expr):
            continue

        required_candidates = [f for f in active if f in LOCK_FIELDS]
        optional_candidates = [f for f in active if f in OPTIONAL_LOCK_FIELDS]

        if required_candidates:
            message = (
                ".clk_lock is unset although the descriptor has "
                + ", ".join("." + f for f in required_candidates)
                + "; the common helper passes mcd->clk_lock to these registration paths"
            )
            if optional_candidates:
                message += "; .composite_clks is also present (its lock is documented as optional)"
            findings.append(Finding(
                file=str(path.relative_to(repo)), descriptor=desc, line=line,
                severity="REVIEW", lock_fields=required_candidates,
                optional_fields=optional_candidates, lock_expression=lock_expr,
                spinlocks_in_file=locks, message=message,
            ))
        elif include_optional and optional_candidates:
            findings.append(Finding(
                file=str(path.relative_to(repo)), descriptor=desc, line=line,
                severity="INFO", optional_fields=optional_candidates,
                lock_expression=lock_expr, spinlocks_in_file=locks,
                message=("only .composite_clks is present; the common helper "
                         "explicitly documents its lock as optional, but shared-register "
                         "read-modify-write interactions may still justify a lock"),
            ))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path, help="Linux source tree")
    parser.add_argument("--file", help="audit one driver file")
    parser.add_argument("--json", type=Path, help="write machine-readable JSON")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress clean summary details")
    parser.add_argument("--include-optional", action="store_true",
                        help="also report composite-only descriptors (their lock is optional in the common helper)")
    parser.add_argument("--fail-on-candidate", action="store_true",
                        help="exit with status 1 when REVIEW candidates are found")
    args = parser.parse_args()

    repo = args.repo.resolve()
    mediatek = repo / "drivers/clk/mediatek"
    if not (mediatek / "clk-mtk.c").is_file():
        parser.error(f"not a Linux tree (missing {mediatek / 'clk-mtk.c'})")

    files = [repo / args.file] if args.file else sorted(mediatek.glob("*.c"))
    findings: list[Finding] = []
    for path in files:
        if not path.is_file() or mediatek not in path.parents:
            continue
        findings.extend(audit_file(repo, path, args.include_optional))

    reviews = [f for f in findings if f.severity == "REVIEW"]
    infos = [f for f in findings if f.severity == "INFO"]
    print(f"MediaTek common-probe descriptors with missing clk_lock candidates: {len(reviews)}")
    if args.include_optional:
        print(f"Composite-only optional-lock review notes:                 {len(infos)}")
    print()

    for finding in findings:
        print(f"[{finding.severity}] {finding.file}:{finding.line}  {finding.descriptor}")
        if finding.lock_fields:
            print("  lock-relevant fields: " + ", ".join(finding.lock_fields))
        if finding.optional_fields:
            print("  optional-lock fields: " + ", ".join(finding.optional_fields))
        if finding.spinlocks_in_file:
            print("  spinlocks declared in file: " + ", ".join(finding.spinlocks_in_file))
        print("  " + finding.message)
        print()

    if args.json:
        args.json.write_text(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
        print(f"JSON: {args.json}")

    return 1 if args.fail_on_candidate and reviews else 0


if __name__ == "__main__":
    raise SystemExit(main())
