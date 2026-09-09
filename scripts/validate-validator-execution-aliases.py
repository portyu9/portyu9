#!/usr/bin/env python3
"""Reject alias/reflection bypasses around mutation and execution-sensitive callables.

The validator-purity firewall intentionally recognizes canonical call spellings so its
small reviewed process allowlist can remain auditable. This companion contract prevents
repository Python from hiding those sensitive callables behind import aliases, direct
callable aliases, reflective lookup, or receiver-typed ambiguous mutation methods before
a call reaches the purity firewall.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SELF = Path(__file__).name

FORBIDDEN_CANONICAL_CALLABLES = {
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
    "os.system", "os.popen", "pty.spawn",
    "exec", "eval", "compile", "__import__",
    "builtins.exec", "builtins.eval", "builtins.compile", "builtins.__import__",
    "open", "builtins.open",
    "importlib.import_module", "runpy.run_module", "runpy.run_path",
    "os.remove", "os.unlink", "os.rename", "os.replace", "os.mkdir", "os.makedirs",
    "os.rmdir", "os.removedirs", "os.chmod", "os.truncate",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
    "shutil.move", "shutil.rmtree",
}
FORBIDDEN_METHOD_LEAVES = {
    "write_text", "write_bytes", "touch", "mkdir", "unlink", "rename", "rmdir",
    "chmod", "symlink_to", "hardlink_to", "apply",
}
PATH_RETURNING_METHODS = {
    "absolute", "expanduser", "joinpath", "relative_to", "resolve",
    "with_name", "with_stem", "with_suffix",
}
SENSITIVE_MODULE_ROOTS = {
    name.split(".", 1)[0]
    for name in FORBIDDEN_CANONICAL_CALLABLES
    if "." in name
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = dotted_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return None


def script_paths() -> list[Path]:
    return sorted(
        path for path in SCRIPTS.glob("*.py")
        if path.name != SELF and path.is_file() and not path.is_symlink()
    )


def is_validator_path(path: Path) -> bool:
    return path.name.startswith("validate-") or path.name.startswith("validate_")


def import_bindings(tree: ast.AST) -> tuple[dict[str, str], dict[str, str], list[str]]:
    modules: dict[str, str] = {}
    symbols: dict[str, str] = {}
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                bound = alias.asname or root
                modules[bound] = alias.name
                if root in SENSITIVE_MODULE_ROOTS and alias.asname is not None:
                    violations.append(
                        f"line {node.lineno}: sensitive module import alias is forbidden: "
                        f"{alias.name} as {alias.asname}"
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            for alias in node.names:
                if alias.name == "*":
                    if root in SENSITIVE_MODULE_ROOTS:
                        violations.append(
                            f"line {node.lineno}: star import from sensitive module is forbidden: {node.module}"
                        )
                    continue
                canonical = f"{node.module}.{alias.name}"
                symbols[alias.asname or alias.name] = canonical
                if canonical in FORBIDDEN_CANONICAL_CALLABLES:
                    violations.append(
                        f"line {node.lineno}: sensitive callable must not be imported by symbol: "
                        f"{canonical}"
                    )
    return modules, symbols, violations


def resolved_name(node: ast.AST, modules: dict[str, str], symbols: dict[str, str]) -> str | None:
    raw = dotted_name(node)
    if not raw:
        return None
    if raw in symbols:
        return symbols[raw]
    first, *rest = raw.split(".")
    if first in modules:
        base = modules[first]
        return ".".join((base, *rest)) if rest else base
    return raw


def parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    result: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            result[child] = parent
    return result


def direct_call_target(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(node)
    return isinstance(parent, ast.Call) and parent.func is node


def annotation_mentions_path(
    node: ast.AST | None,
    modules: dict[str, str],
    symbols: dict[str, str],
) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        compact = node.value.replace(" ", "")
        return compact == "Path" or "Path" in compact.split("|")
    resolved = resolved_name(node, modules, symbols)
    if resolved in {"Path", "pathlib.Path"}:
        return True
    if isinstance(node, ast.Subscript):
        return annotation_mentions_path(node.slice, modules, symbols)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return (
            annotation_mentions_path(node.left, modules, symbols)
            or annotation_mentions_path(node.right, modules, symbols)
        )
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(annotation_mentions_path(item, modules, symbols) for item in node.elts)
    return False


class PathMutationVisitor(ast.NodeVisitor):
    """Resolve unambiguous pathlib receivers without conflating str.replace()."""

    def __init__(
        self,
        path: Path,
        modules: dict[str, str],
        symbols: dict[str, str],
        parents: dict[ast.AST, ast.AST],
    ) -> None:
        self.path = path
        self.modules = modules
        self.symbols = symbols
        self.parents = parents
        self.global_paths: set[str] = set()
        self.scopes: list[set[str]] = []
        self.violations: list[str] = []

    @property
    def paths(self) -> set[str]:
        return self.scopes[-1] if self.scopes else self.global_paths

    def report(self, node: ast.AST, message: str) -> None:
        self.violations.append(f"line {getattr(node, 'lineno', '?')}: {message}")

    def is_path_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.paths
        if isinstance(node, ast.Call):
            name = resolved_name(node.func, self.modules, self.symbols)
            if name in {"Path", "pathlib.Path"}:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in PATH_RETURNING_METHODS:
                return self.is_path_expr(node.func.value)
            return False
        if isinstance(node, ast.Attribute):
            if node.attr == "parent":
                return self.is_path_expr(node.value)
            if node.attr == "parents":
                return self.is_path_expr(node.value)
            return False
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
                return self.is_path_expr(node.value.value)
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.is_path_expr(node.left)
        return False

    def bind_target(self, target: ast.AST, is_path: bool) -> None:
        if isinstance(target, ast.Name):
            if is_path:
                self.paths.add(target.id)
            else:
                self.paths.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind_target(item, False)

    def visit_Module(self, node: ast.Module) -> None:
        # Establish module-level Path bindings before function bodies are inspected so
        # functions may safely reference constants such as ROOT and SCRIPTS.
        changed = True
        while changed:
            before = set(self.global_paths)
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    is_path = self.is_path_expr(statement.value)
                    for target in statement.targets:
                        if isinstance(target, ast.Name) and is_path:
                            self.global_paths.add(target.id)
                elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    is_path = annotation_mentions_path(statement.annotation, self.modules, self.symbols)
                    if statement.value is not None:
                        is_path = is_path or self.is_path_expr(statement.value)
                    if is_path:
                        self.global_paths.add(statement.target.id)
            changed = before != self.global_paths

        for statement in node.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        local = set(self.global_paths)
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if annotation_mentions_path(arg.annotation, self.modules, self.symbols):
                local.add(arg.arg)
        if node.args.vararg and annotation_mentions_path(node.args.vararg.annotation, self.modules, self.symbols):
            local.add(node.args.vararg.arg)
        if node.args.kwarg and annotation_mentions_path(node.args.kwarg.annotation, self.modules, self.symbols):
            local.add(node.args.kwarg.arg)
        self.scopes.append(local)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        is_path = self.is_path_expr(node.value)
        for target in node.targets:
            self.bind_target(target, is_path)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        is_path = annotation_mentions_path(node.annotation, self.modules, self.symbols)
        if node.value is not None:
            is_path = is_path or self.is_path_expr(node.value)
        self.bind_target(node.target, is_path)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
            if self.is_path_expr(node.func.value):
                self.report(
                    node,
                    "pathlib.Path.replace() filesystem mutation is forbidden in validator production code",
                )
        call_name = resolved_name(node.func, self.modules, self.symbols)
        if call_name == "getattr" and len(node.args) >= 2:
            attribute = (
                node.args[1].value
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                else None
            )
            if attribute == "replace" and self.is_path_expr(node.args[0]):
                self.report(
                    node,
                    "reflective pathlib.Path.replace lookup is forbidden in validator production code",
                )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "replace" and self.is_path_expr(node.value):
            # Direct calls are reported by visit_Call; this catches bound-method aliasing.
            if not direct_call_target(node, self.parents):
                self.report(
                    node,
                    "pathlib.Path.replace bound method must not be aliased in validators",
                )
        self.generic_visit(node)


def inspect_path_mutations(
    path: Path,
    tree: ast.AST,
    modules: dict[str, str],
    symbols: dict[str, str],
    parents: dict[ast.AST, ast.AST],
) -> list[str]:
    if not is_validator_path(path):
        return []
    visitor = PathMutationVisitor(path, modules, symbols, parents)
    visitor.visit(tree)
    return visitor.violations


def inspect_source(path: Path, source: str) -> list[str]:
    tree = ast.parse(source, filename=str(path))
    modules, symbols, violations = import_bindings(tree)
    parents = parent_map(tree)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Name, ast.Attribute)):
            resolved = resolved_name(node, modules, symbols)
            if resolved in FORBIDDEN_CANONICAL_CALLABLES and not direct_call_target(node, parents):
                violations.append(
                    f"line {getattr(node, 'lineno', '?')}: sensitive callable reference must remain "
                    f"a direct canonical call target: {resolved}"
                )
            if (
                isinstance(node, ast.Attribute)
                and node.attr in FORBIDDEN_METHOD_LEAVES
                and not direct_call_target(node, parents)
            ):
                violations.append(
                    f"line {node.lineno}: mutation-capable bound method must not be aliased: {node.attr}"
                )
            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                target = resolved_name(node.value, modules, symbols)
                if target and target.split(".", 1)[0] in SENSITIVE_MODULE_ROOTS:
                    violations.append(
                        f"line {node.lineno}: reflective namespace access is forbidden for sensitive module: {target}"
                    )

        if not isinstance(node, ast.Call):
            continue
        call_name = resolved_name(node.func, modules, symbols)
        if call_name == "getattr" and len(node.args) >= 2:
            target = resolved_name(node.args[0], modules, symbols)
            attribute = (
                node.args[1].value
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                else None
            )
            if (
                (target and target.split(".", 1)[0] in SENSITIVE_MODULE_ROOTS)
                or attribute in FORBIDDEN_METHOD_LEAVES
            ):
                violations.append(
                    f"line {node.lineno}: reflective getattr can hide a mutation/execution-sensitive callable"
                )
        if call_name == "vars" and node.args:
            target = resolved_name(node.args[0], modules, symbols)
            if target and target.split(".", 1)[0] in SENSITIVE_MODULE_ROOTS:
                violations.append(
                    f"line {node.lineno}: vars() reflection is forbidden for sensitive module: {target}"
                )

    violations.extend(inspect_path_mutations(path, tree, modules, symbols, parents))
    return violations


def self_test() -> None:
    fixture = Path("fixture.py")
    accepted = (
        "import os\nimport subprocess\n"
        "def read(p):\n"
        "    value = p.read_text()\n"
        "    return os.environ.get('X', '') + value\n"
    )
    require(not inspect_source(fixture, accepted), "canonical read-only fixture must pass")

    rejected = {
        "module alias": "import subprocess as sp\ndef f():\n    sp.run(['git', 'status'])\n",
        "symbol alias": "from subprocess import run as runner\ndef f():\n    runner(['git', 'status'])\n",
        "callable alias": "import subprocess\ndef f():\n    runner = subprocess.run\n    runner(['git', 'status'])\n",
        "bound method alias": "def f(p):\n    writer = p.write_text\n    writer('x')\n",
        "reflective process lookup": "import subprocess\ndef f():\n    getattr(subprocess, 'run')(['git', 'status'])\n",
        "reflective method lookup": "def f(p):\n    getattr(p, 'write_text')('x')\n",
        "namespace reflection": "import subprocess\ndef f():\n    return subprocess.__dict__['run'](['git'])\n",
        "vars reflection": "import subprocess\ndef f():\n    return vars(subprocess)['run'](['git'])\n",
        "builtin alias": "def f():\n    evaluator = eval\n    return evaluator('1+1')\n",
    }
    for label, source in rejected.items():
        require(inspect_source(fixture, source), f"self-test accepted {label}")

    validator = Path("validate-fixture.py")
    require(
        not inspect_source(validator, "def f(s):\n    return s.replace('a', 'b')\n"),
        "string replace fixture must remain valid",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f():\n    Path('a').replace('b')\n",
        ),
        "direct Path.replace fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    p.replace(Path('b'))\n",
        ),
        "annotated Path.replace fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f():\n    p = Path('a')\n    q = p.resolve()\n    mover = q.replace\n    mover('b')\n",
        ),
        "propagated Path.replace bound-method alias fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    getattr(p, 'replace')('b')\n",
        ),
        "reflective Path.replace fixture must fail",
    )
    require(
        not inspect_source(
            Path("generate-fixture.py"),
            "from pathlib import Path\ndef f():\n    Path('a').replace('b')\n",
        ),
        "transformer/generator Path.replace fixture must remain outside validator purity scope",
    )


def main() -> int:
    try:
        self_test()
        paths = script_paths()
        require(paths, "no repository Python scripts discovered")
        violations: list[str] = []
        for path in paths:
            for violation in inspect_source(path, path.read_text(encoding="utf-8")):
                violations.append(f"{path.name}: {violation}")
        if violations:
            raise ValueError(
                "indirect mutation/execution callable violations:\n  " + "\n  ".join(violations)
            )
        print(
            f"Validator execution alias contract passed: {len(paths)} repository Python scripts "
            "use mutation/execution-sensitive callables only through canonical auditable spellings; "
            "validator Path.replace mutation is receiver-aware and closed without conflating str.replace"
        )
        return 0
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
