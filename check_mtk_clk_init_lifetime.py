#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Find init-section data that may outlive init in MediaTek clock drivers.

Run from a Linux source tree:
    python3 check_mtk_clk_init_lifetime.py /path/to/linux

The checker is intentionally conservative and scoped to drivers/clk/mediatek.
It looks for two classes of lifetime hazards:

  * Descriptor arrays referenced by mtk_clk_desc objects used by the common
    probe/remove helpers. The common remove path re-reads these arrays to find
    clock IDs, so their storage must survive init memory reclamation.
  * Descriptor types retained directly by runtime clock objects. In the
    current MediaTek implementation, gates, muxes, PLLs, and reset controllers
    retain pointers to their descriptor data. Selected nested objects (gate
    register layouts, mux parent-index tables, reset offset/index tables) are
    checked as well.

This is a source-pattern checker, not a C parser. Review every finding and use
compiler/sparse/runtime testing for final validation. It deliberately does
not flag parent-name arrays merely passed as clk_init_data.parent_names:
CCF copies those strings during registration.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

TARGET_DIR = Path("drivers/clk/mediatek")

# mtk_clk_desc fields whose values are pointers to clock/reset descriptor data.
# For every field below, common remove walks the pointed-to descriptor(s),
# directly or through the matching unregister helper.
DESC_FIELDS = {
    "clks",
    "composite_clks",
    "divider_clks",
    "fixed_clks",
    "factor_clks",
    "mux_clks",
    "cpumuxes",
    "plls",
    "rst_desc",
    "clk_lock",
}

# These descriptors are retained by runtime MediaTek clock objects, rather
# than just being consumed during registration.
RUNTIME_RETAINED_TYPES = {
    "mtk_gate": (
        "clk-gate.c stores the descriptor in struct mtk_clk_gate::gate; "
        "clock operations dereference it at runtime",
    ),
    "mtk_mux": (
        "clk-mux.c stores the descriptor in struct mtk_clk_mux::data; "
        "clock operations dereference it at runtime",
    ),
    "mtk_pll_data": (
        "clk-pll.c stores the descriptor in struct mtk_clk_pll::data; "
        "PLL operations dereference it at runtime",
    ),
    "mtk_clk_rst_desc": (
        "reset.c stores the descriptor in struct mtk_clk_rst_data::desc; "
        "reset operations dereference it at runtime",
    ),
}

STRUCT_DECL_RE = re.compile(
    r"\bstatic\s+(?:(?:const|volatile|unsigned|signed|long|short)\s+)*"
    r"(?:(?:struct\s+(?P<struct_type>[A-Za-z_]\w*))|(?P<base_type>[A-Za-z_]\w*))"
    r"\s*(?:\*\s*(?:(?:const|volatile)\s*)?)*\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?P<array>\[[^\]]*\])?\s*"
    r"(?P<annotation>__initconst|__initdata)\b"
)
DESC_DECL_RE = re.compile(
    r"\bstatic\s+(?:(?:const|volatile)\s+)*struct\s+mtk_clk_desc\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*=\s*\{"
)
STRUCT_INIT_RE = re.compile(
    r"\bstatic\s+(?:(?:const|volatile)\s+)*struct\s+"
    r"(?P<type>[A-Za-z_]\w*)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*\{"
)
FIELD_RE = re.compile(
    r"\.(?P<field>[A-Za-z_]\w*)\s*=\s*&?\s*(?P<value>[A-Za-z_]\w*)\b"
)
COMMON_PROBE_RE = re.compile(
    r"\.probe\s*=\s*mtk_clk_(?:simple|pdev)_probe\b|"
    r"\bmtk_clk_(?:simple|pdev)_probe\s*\("
)
COMMON_REMOVE_RE = re.compile(
    r"\.remove\s*=\s*mtk_clk_(?:simple|pdev)_remove\b|"
    r"\bmtk_clk_(?:simple|pdev)_remove\s*\("
)


@dataclass(frozen=True)
class Declaration:
    name: str
    ctype: str
    annotation: str
    line: int
    is_array: bool


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    symbol: str
    ctype: str
    annotation: str
    confidence: str
    reason: str


def mask_comments_and_literals(source: str) -> str:
    """Blank comments and string/character literals, preserving offsets/lines."""
    out = list(source)
    i = 0
    n = len(source)
    state = "code"

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if state == "code":
            if ch == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            if ch == "/" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if ch == '"':
                out[i] = " "
                state = "string"
            elif ch == "'":
                out[i] = " "
                state = "char"
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
            else:
                if ch != "\n":
                    out[i] = " "
                i += 1
            continue

        if state == "line_comment":
            if ch == "\n":
                state = "code"
            else:
                out[i] = " "
            i += 1
            continue

        # String / character literal. Preserve escaped newlines and offsets.
        if ch == "\\":
            out[i] = " " if ch != "\n" else ch
            if i + 1 < n:
                if source[i + 1] != "\n":
                    out[i + 1] = " "
                i += 2
            else:
                i += 1
            continue
        if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
            out[i] = " "
            state = "code"
        elif ch != "\n":
            out[i] = " "
        i += 1

    return "".join(out)


def matching_brace(code: str, open_pos: int) -> int | None:
    depth = 0
    for i in range(open_pos, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def declarations(code: str) -> dict[str, Declaration]:
    result: dict[str, Declaration] = {}
    for match in STRUCT_DECL_RE.finditer(code):
        line = code.count("\n", 0, match.start()) + 1
        decl = Declaration(
            name=match.group("name"),
            ctype=match.group("struct_type") or match.group("base_type"),
            annotation=match.group("annotation"),
            line=line,
            is_array=match.group("array") is not None,
        )
        result[decl.name] = decl
    return result


def initializer_blocks(code: str, pattern: re.Pattern[str]) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for match in pattern.finditer(code):
        open_pos = code.find("{", match.start())
        close_pos = matching_brace(code, open_pos)
        if close_pos is None:
            continue
        result[match.group("name")] = (
            match.groupdict().get("type", "mtk_clk_desc"),
            code[open_pos + 1 : close_pos],
        )
    return result


def descriptor_initializers(code: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in DESC_DECL_RE.finditer(code):
        open_pos = code.find("{", match.start())
        close_pos = matching_brace(code, open_pos)
        if close_pos is None:
            continue
        result[match.group("name")] = code[open_pos + 1 : close_pos]
    return result


def referenced_descriptor_names(code: str) -> set[str]:
    """Find mtk_clk_desc names passed through an OF match table .data field."""
    names: set[str] = set()
    # Typical pattern: { .compatible = "...", .data = &topck_desc }
    for match in re.finditer(r"\.data\s*=\s*&?\s*([A-Za-z_]\w*)\b", code):
        names.add(match.group(1))
    return names


def scan_file(path: Path, root: Path) -> list[Finding]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    code = mask_comments_and_literals(raw)
    decls = declarations(code)
    descs = descriptor_initializers(code)
    typed_inits = initializer_blocks(code, STRUCT_INIT_RE)
    referenced_descs = referenced_descriptor_names(code)
    has_common_probe = bool(COMMON_PROBE_RE.search(code))
    has_common_remove = bool(COMMON_REMOVE_RE.search(code))

    findings: dict[str, Finding] = {}

    def add(decl: Declaration, confidence: str, reason: str) -> None:
        findings[decl.name] = Finding(
            path=str(path.relative_to(root)),
            line=decl.line,
            symbol=decl.name,
            ctype=decl.ctype + ("[]" if decl.is_array else ""),
            annotation=decl.annotation,
            confidence=confidence,
            reason=reason,
        )

    # Directly retained descriptor pointers: these are unsafe independently
    # of whether a remove callback exists.
    for decl in decls.values():
        if decl.ctype in RUNTIME_RETAINED_TYPES:
            # Require evidence that this type participates in a registration
            # path in this file; avoids reporting unrelated dead declarations.
            registration = {
                "mtk_gate": r"\bmtk_clk_register_gates\s*\(|\.clks\s*=",
                "mtk_mux": r"\bmtk_clk_register_muxes\s*\(|\.mux_clks\s*=",
                "mtk_pll_data": r"\bmtk_clk_register_plls\s*\(|\.plls\s*=",
                "mtk_clk_rst_desc": r"\bmtk_register_reset_controller_with_dev\s*\(|\.rst_desc\s*=",
            }[decl.ctype]
            if re.search(registration, code):
                add(decl, "HIGH", RUNTIME_RETAINED_TYPES[decl.ctype])

    # The gate descriptor points to register-layout objects which are also
    # dereferenced by runtime gate callbacks. Catch init-only layout objects.
    has_gate_registration = bool(
        re.search(r"\bmtk_clk_register_gates\s*\(|\.clks\s*=", code)
    )
    if has_gate_registration:
        for decl in decls.values():
            if decl.ctype != "mtk_gate_regs":
                continue
            if re.search(r"&\s*" + re.escape(decl.name) + r"\b", code):
                add(
                    decl,
                    "HIGH",
                    "a registered mtk_gate descriptor references this register-layout "
                    "object, and runtime gate operations dereference gate->regs",
                )

    # Follow selected pointers embedded in retained descriptor objects.
    # reset.c keeps mtk_clk_rst_desc and dereferences rst_bank_ofs/rst_idx_map;
    # clk-mux.c keeps mtk_mux and dereferences parent_index at runtime.
    nested_fields = {
        "mtk_clk_rst_desc": {"rst_bank_ofs", "rst_idx_map"},
        "mtk_mux": {"parent_index"},
    }
    for owner_name, (owner_type, body) in typed_inits.items():
        fields = nested_fields.get(owner_type)
        if not fields:
            continue
        for field_match in FIELD_RE.finditer(body):
            if field_match.group("field") not in fields:
                continue
            target = decls.get(field_match.group("value"))
            if target:
                add(
                    target,
                    "HIGH",
                    f"{owner_name}.{field_match.group('field')} is retained and "
                    f"dereferenced through struct {owner_type} at runtime",
                )

    # Indexed mux macros may assign parent_index positionally, so also match
    # explicit designated initializers outside the simple block parser.
    for decl in decls.values():
        if re.search(r"\.parent_index\s*=\s*&?\s*" +
                      re.escape(decl.name) + r"\b", code):
            if re.search(r"\bmtk_clk_register_muxes\s*\(|\.mux_clks\s*=", code):
                add(
                    decl,
                    "HIGH",
                    "this array is assigned to mtk_mux.parent_index, which "
                    "clk-mux.c dereferences after registration",
                )

    # If a common-helper descriptor is used by the common remove path, every
    # descriptor pointer stored in it must survive until remove/unregister.
    if has_common_probe and has_common_remove:
        for desc_name, body in descs.items():
            # Descriptor must actually be referenced by the match-data table.
            if desc_name not in referenced_descs:
                continue
            for field_match in FIELD_RE.finditer(body):
                field = field_match.group("field")
                value = field_match.group("value")
                if field not in DESC_FIELDS:
                    continue
                decl = decls.get(value)
                if decl:
                    add(
                        decl,
                        "HIGH",
                        f"{desc_name}.{field} points to this object; "
                        "mtk_clk_simple_remove()/mtk_clk_pdev_remove() "
                        "passes it to the corresponding unregister path, "
                        "which re-reads descriptor entries",
                    )

            # The mtk_clk_desc itself is fetched again during remove, so it
            # must not be discarded with init memory either.
            desc_decl = decls.get(desc_name)
            if desc_decl:
                add(
                    desc_decl,
                    "HIGH",
                    "the descriptor is match data for a common probe/remove "
                    "driver and is fetched again by the remove helper",
                )

    # Also handle legacy/custom remove code that calls MTK unregister helpers
    # directly rather than using mtk_clk_desc.
    unregister_calls = {
        "mtk_gate": r"\bmtk_clk_unregister_gates\s*\(",
        "mtk_composite": r"\bmtk_clk_unregister_composites\s*\(|"
        r"\bmtk_clk_unregister_cpumuxes\s*\(",
        "mtk_clk_divider": r"\bmtk_clk_unregister_dividers\s*\(",
        "mtk_fixed_clk": r"\bmtk_clk_unregister_fixed_clks\s*\(",
        "mtk_fixed_factor": r"\bmtk_clk_unregister_factors\s*\(",
        "mtk_mux": r"\bmtk_clk_unregister_muxes\s*\(",
        "mtk_pll_data": r"\bmtk_clk_unregister_plls\s*\(",
    }
    for decl in decls.values():
        pattern = unregister_calls.get(decl.ctype)
        if pattern and re.search(pattern, code):
            add(
                decl,
                "MEDIUM",
                "init-only object is in a source file that explicitly calls the "
                "matching unregister helper; verify that the call uses this object",
            )

    return sorted(findings.values(), key=lambda item: (item.line, item.symbol))


def run_self_tests() -> int:
    fixtures = {
        "cpumux_common_remove": r'''
            static const struct mtk_composite cpu_muxes[] __initconst = { };
            static const struct mtk_clk_desc infra_desc = {
                .cpumuxes = cpu_muxes,
                .num_cpumuxes = ARRAY_SIZE(cpu_muxes),
            };
            static const struct of_device_id match[] = {
                { .compatible = "x", .data = &infra_desc },
            };
            static struct platform_driver drv = {
                .probe = mtk_clk_simple_probe,
                .remove = mtk_clk_simple_remove,
            };
        ''',
        "mt8167_top_muxes_regression": r'''
            static struct mtk_composite top_muxes[] __initdata = { };
            static const struct mtk_clk_desc topck_desc = {
                .composite_clks = top_muxes,
            };
            static const struct of_device_id match[] = {
                { .data = &topck_desc },
            };
            static struct platform_driver drv = {
                .probe = mtk_clk_simple_probe, .remove = mtk_clk_simple_remove,
            };
        ''',
        "mt8516_multiple_descriptor_regression": r'''
            static const struct mtk_fixed_clk fixed_clks[] __initconst = { };
            static const struct mtk_fixed_factor top_divs[] __initconst = { };
            static struct mtk_composite top_muxes[] __initdata = { };
            static const struct mtk_composite ifr_muxes[] __initconst = { };
            static const struct mtk_clk_desc topck_desc = {
                .fixed_clks = fixed_clks, .factor_clks = top_divs,
                .composite_clks = top_muxes,
            };
            static const struct mtk_clk_desc infra_desc = {
                .composite_clks = ifr_muxes,
            };
            static const struct of_device_id match[] = {
                { .data = &topck_desc }, { .data = &infra_desc },
            };
            static struct platform_driver drv = {
                .probe = mtk_clk_simple_probe, .remove = mtk_clk_simple_remove,
            };
        ''',
        "fixed_factor_common_remove": r'''
            static const struct mtk_fixed_factor divs[] __initconst = { };
            static const struct mtk_clk_desc desc = { .factor_clks = divs };
            static const struct of_device_id match[] = {
                { .data = &desc },
            };
            static struct platform_driver drv = {
                .probe = mtk_clk_pdev_probe,
                .remove = mtk_clk_pdev_remove,
            };
        ''',
        "runtime_gate_retention": r'''
            static const struct mtk_gate gates[] __initconst = { GATE_X(&regs) };
            static const struct mtk_gate_regs regs __initconst = { };
            static struct platform_driver drv = { .probe = mtk_clk_simple_probe };
            static const struct mtk_clk_desc desc = { .clks = gates };
        ''',
        "reset_nested_array": r'''
            static const u16 rst_offsets[] __initconst = { 0x10, 0x14 };
            static const struct mtk_clk_rst_desc rst_desc = {
                .version = MTK_RST_SIMPLE, .rst_bank_ofs = rst_offsets,
            };
            static const struct mtk_clk_desc desc = { .rst_desc = &rst_desc };
            static const struct of_device_id match[] = { { .data = &desc } };
            static struct platform_driver drv = {
                .probe = mtk_clk_simple_probe, .remove = mtk_clk_simple_remove,
            };
        ''',
        "parent_names_are_not_flagged": r'''
            static const char * const parents[] __initconst = { "p0", "p1" };
            static const struct mtk_composite muxes[] = { };
            static const struct mtk_clk_desc desc = { .composite_clks = muxes };
            static const struct of_device_id match[] = { { .data = &desc } };
            static struct platform_driver drv = {
                .probe = mtk_clk_simple_probe,
                .remove = mtk_clk_simple_remove,
            };
        ''',
        "descriptor_itself_is_not_init": r'''
            static const struct mtk_clk_desc desc = { };
            static const struct of_device_id match[] = { { .data = &desc } };
            static struct platform_driver drv = {
                .probe = mtk_clk_simple_probe,
                .remove = mtk_clk_simple_remove,
            };
        ''',
    }
    expected = {
        "cpumux_common_remove": {"cpu_muxes"},
        "mt8167_top_muxes_regression": {"top_muxes"},
        "mt8516_multiple_descriptor_regression": {
            "fixed_clks", "top_divs", "top_muxes", "ifr_muxes"
        },
        "fixed_factor_common_remove": {"divs"},
        "runtime_gate_retention": {"gates", "regs"},
        "reset_nested_array": {"rst_offsets"},
        "parent_names_are_not_flagged": set(),
        "descriptor_itself_is_not_init": set(),
    }
    for name, source in fixtures.items():
        temp = Path(f"/tmp/{name}.c")
        temp.write_text(source)
        try:
            actual = {f.symbol for f in scan_file(temp, Path("/tmp"))}
        finally:
            temp.unlink(missing_ok=True)
        if actual != expected[name]:
            print(
                f"FAIL {name}: expected {sorted(expected[name])}, "
                f"got {sorted(actual)}",
                file=sys.stderr,
            )
            return 1
        print(f"PASS {name}")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path("."),
        help="Linux source tree (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit findings as JSON instead of human-readable text",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run built-in synthetic parser tests",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_tests()

    root = args.root.resolve()
    source_dir = root / TARGET_DIR
    if not source_dir.is_dir():
        parser.error(f"{source_dir} is not a directory")

    findings: list[Finding] = []
    for path in sorted(source_dir.glob("*.c")):
        findings.extend(scan_file(path, root))

    findings.sort(key=lambda item: (item.path, item.line, item.symbol))

    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    elif not findings:
        print("No init-section lifetime candidates found.")
    else:
        for item in findings:
            print(
                f"{item.confidence}: {item.path}:{item.line}: "
                f"{item.symbol} ({item.ctype}, {item.annotation})"
            )
            print(f"    {item.reason}")
        print(f"\n{len(findings)} candidate(s) found.")
        print("Review each candidate; this is a source-pattern checker, not proof.")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
