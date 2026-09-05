#!/usr/bin/env python3
"""Fail closed when production validators contain filesystem mutation behavior.

Validator modules are observers. They may read files, parse contracts, perform network
reads, and fail, but production validation paths must not rewrite the evidence they are
claiming to validate. Explicit transformer/generator scripts own mutation instead.

Self-test functions are exempt because they may create isolated temporary fixtures.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SELF = Path(__file__).name

# Attribute-only calls must be unambiguous enough to classify without type inference.
# `replace()` is intentionally absent because str.replace() is common; os.replace()
# remains forbidden through the qualified OS_MUTATORS check below.
WRITE_METHODS = {
    "write_text",
    "write_bytes",
    "touch",
    "mkdir",
    "unlink",
    "rename",
    "rmdir",
    "chmod",
    "symlink_to",
    "hardlink_to",
}
MUTATOR_METHODS = {"apply"}
OS_MUTATORS = {
    "remove",
    "unlink",
    "rename",
    "replace",
    "mkdir",
    "makedirs",
    "rmdir",
    "removedirs",
    "chmod",
    "truncate",
}
SHUTIL_MUTATORS = {"copy", "copy2", "copyfile", "copytree", "move", "rmtree"}
WRITE_MODE_MARKERS = frozenset("wax+")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validator_paths() -> list[Path]:
    paths = {
        *SCRIPTS.glob("validate-*.py"),
        *SCRIPTS.glob("validate_*.py"),
    }
    return sorted(path for path in paths if path.name != SELF)


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = dotted_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return None


def literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class PurityVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.functions: list[str] = []
        self.violations: list[str] = []

    @property
    def exempt_self_test(self) -> bool:
        return any(name == "self_test" or name.startswith("self_test_") for name in self.functions)

    def report(self, node: ast.AST, message: str) -> None:
        if not self.exempt_self_test:
            self.violations.append(f"{self.path.name}:{getattr(node, 'lineno', '?')}: {message}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func) or ""
        leaf = name.rsplit(".", 1)[-1]

        if leaf in WRITE_METHODS:
            self.report(node, f"filesystem mutation method is forbidden in production validators: {leaf}()")
        if leaf in MUTATOR_METHODS:
            self.report(node, f"transformer-style mutation call is forbidden in production validators: {leaf}()")
        if name in {f"os.{item}" for item in OS_MUTATORS}:
            self.report(node, f"OS filesystem mutation is forbidden in production validators: {name}()")
        if name in {f"shutil.{item}" for item in SHUTIL_MUTATORS}:
            self.report(node, f"shutil filesystem mutation is forbidden in production validators: {name}()")

        if name == "open" or leaf == "open":
            mode_node: ast.AST | None = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode_node = keyword.value
            mode = literal_string(mode_node) if mode_node is not None else "r"
            if mode is None:
                self.report(node, "dynamic open() mode is forbidden in production validators")
            elif any(marker in mode for marker in WRITE_MODE_MARKERS):
                self.report(node, f"write-capable open() mode is forbidden in production validators: {mode!r}")

        self.generic_visit(node)


def inspect_source(path: Path, source: str) -> list[str]:
    tree = ast.parse(source, filename=str(path))
    visitor = PurityVisitor(path)
    visitor.visit(tree)
    return visitor.violations


def self_test() -> None:
    fixture = Path("validate-fixture.py")
    require(not inspect_source(fixture, "def validate(p):\n    return p.read_text()\n"), "read-only fixture must pass")
    require(not inspect_source(fixture, "def validate(s):\n    return s.replace('a', 'b')\n"), "string replace fixture must pass")
    require(inspect_source(fixture, "def validate(p):\n    p.write_text('x')\n"), "write_text fixture must fail")
    require(inspect_source(fixture, "def validate(p):\n    open(p, 'wb')\n"), "write-mode open fixture must fail")
    require(inspect_source(fixture, "def validate(m, p):\n    m.apply(p)\n"), "transformer apply fixture must fail")
    require(inspect_source(fixture, "def validate(a, b):\n    os.replace(a, b)\n"), "qualified os.replace fixture must fail")
    require(
        not inspect_source(fixture, "def self_test(p):\n    p.write_text('fixture')\n"),
        "isolated self-test fixture mutation must be exempt",
    )
    print("Validator purity firewall self-test passed")


def main() -> int:
    try:
        self_test()
        paths = validator_paths()
        require(paths, "no validator modules discovered")
        violations: list[str] = []
        for path in paths:
            violations.extend(inspect_source(path, path.read_text(encoding="utf-8")))
        if violations:
            raise ValueError("validator purity violations:\n  " + "\n  ".join(violations))
        print(f"Validator purity passed: {len(paths)} validator modules are production read-only")
        return 0
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
