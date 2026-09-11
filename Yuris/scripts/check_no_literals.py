"""Gate: structural logic contains no engine-specific literals.

Engine values belong in the dialect module so they can be traced to evidence,
tested and reused. This searches the structural modules for hex magics, byte
signatures, opcode tables and inline regexes.

Calibrated in both directions: a well-layered implementation must report zero,
and a mixed-layer one must report its violations. Ambiguous cases (plain decimal
numbers) are advisories, not failures — reporting them as failures trains people
to ignore the gate.

Exit code 0 when there are no violations, 1 otherwise.  JSON report on stdout.
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

# Hex values that are generic bit manipulation rather than engine identity.
GENERIC_HEX = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x7, 0x8, 0xF, 0x10, 0x1F, 0x20, 0x3F, 0x7F,
    0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFF00, 0xFF0000, 0xFFFF0000,
}
EXEMPT_COMMENT = "dialect-literal-ok"
REGEX_CALLS = {"compile", "match", "search", "findall", "finditer", "sub", "subn", "fullmatch"}


class Scanner(ast.NodeVisitor):
    def __init__(self, source: str, path: pathlib.Path) -> None:
        self.path = path
        self.lines = source.splitlines()
        self.violations: list[dict] = []
        self.advisories: list[dict] = []

    def exempt(self, node: ast.AST) -> bool:
        line = self.lines[node.lineno - 1] if 0 < node.lineno <= len(self.lines) else ""
        return EXEMPT_COMMENT in line

    def record(self, bucket: list[dict], code: str, node: ast.AST, detail: str) -> None:
        if self.exempt(node):
            return
        bucket.append({
            "code": code,
            "file": self.path.name,
            "line": node.lineno,
            "detail": detail,
        })

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, bool):
            return
        if isinstance(node.value, int):
            raw = self.lines[node.lineno - 1] if 0 < node.lineno <= len(self.lines) else ""
            hexish = f"0x{node.value:x}" in raw.lower() or f"0x{node.value:X}" in raw
            if hexish and node.value not in GENERIC_HEX:
                self.record(self.violations, "HEX_MAGIC", node,
                            f"hex literal 0x{node.value:X} outside the dialect")
            elif not hexish and abs(node.value) > 64:
                self.record(self.advisories, "DECIMAL_LITERAL", node,
                            f"literal {node.value}: is this an undeclared window constant?")
        elif isinstance(node.value, bytes) and len(node.value) >= 2:
            self.record(self.violations, "BYTE_SIGNATURE", node,
                        f"byte string {node.value!r} outside the dialect")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        function = node.func
        module = getattr(getattr(function, "value", None), "id", None)
        name = getattr(function, "attr", None)
        if module == "re" and name in REGEX_CALLS:
            self.record(self.violations, "INLINE_REGEX", node,
                        f"re.{name} in structural logic; declare the pattern in the dialect")
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        # An opcode/ID table: several integer keys mapping to strings.
        integer_keys = [
            k for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, int)
            and not isinstance(k.value, bool)
        ]
        string_values = [
            v for v in node.values
            if isinstance(v, ast.Constant) and isinstance(v.value, str)
        ]
        if len(integer_keys) >= 2 and len(string_values) >= 2:
            self.record(self.violations, "OPCODE_TABLE", node,
                        f"{len(integer_keys)} integer keys mapped to names; "
                        "this table belongs in the dialect")
        self.generic_visit(node)


def scan(path: pathlib.Path) -> tuple[list[dict], list[dict]]:
    source = path.read_text(encoding="utf-8")
    scanner = Scanner(source, path)
    scanner.visit(ast.parse(source, filename=str(path)))
    return scanner.violations, scanner.advisories


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", type=pathlib.Path, help="file or directory to scan")
    parser.add_argument("--exclude", action="append", default=[],
                        help="module stem to skip (the dialect module)")
    args = parser.parse_args(argv)

    if args.target.is_file():
        files = [args.target]
    else:
        files = sorted(
            p for p in args.target.glob("*.py")
            if p.stem not in args.exclude and not p.stem.startswith("check_")
        )
    violations: list[dict] = []
    advisories: list[dict] = []
    for path in files:
        found, advised = scan(path)
        violations.extend(found)
        advisories.extend(advised)

    print(json.dumps({
        "gate": "no_literals",
        "scanned": [p.name for p in files],
        "violations": violations,
        "advisories": advisories,
        "passed": not violations,
    }, ensure_ascii=False, indent=2))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
