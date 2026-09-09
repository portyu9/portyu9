#!/usr/bin/env python3
"""Reject alias/reflection bypasses around mutation and execution-sensitive callables.

The validator-purity firewall intentionally recognizes canonical call spellings so its
small reviewed process allowlist can remain auditable. This companion contract prevents
repository Python from hiding those sensitive callables behind import aliases, direct
callable aliases, reflective lookup, receiver-typed ambiguous mutation methods, or
low-level descriptor/file-metadata mutation surfaces before a call reaches the purity
firewall.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SELF = Path(__file__).name

VALIDATOR_ALWAYS_FORBIDDEN_CALLABLES = {
    "os.chflags", "os.chown", "os.copy_file_range", "os.fchmod", "os.fchown",
    "os.ftruncate", "os.lchflags", "os.lchown", "os.link", "os.mkfifo", "os.mknod",
    "os.posix_fallocate", "os.pwrite", "os.removexattr", "os.renames", "os.sendfile",
    "os.setxattr", "os.splice", "os.symlink", "os.utime", "os.write", "os.writev",
    "shutil.chown", "shutil.copyfileobj", "shutil.copymode", "shutil.copystat",
    "shutil.make_archive", "shutil.unpack_archive",
}
MODE_SENSITIVE_CANONICAL_CALLABLES = {"io.open", "os.fdopen", "os.open"}
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
} | VALIDATOR_ALWAYS_FORBIDDEN_CALLABLES | MODE_SENSITIVE_CANONICAL_CALLABLES
FORBIDDEN_METHOD_LEAVES = {
    "write_text", "write_bytes", "touch", "mkdir", "unlink", "rename", "rmdir",
    "chmod", "lchmod", "symlink_to", "hardlink_to", "apply",
}
CONCRETE_PATH_TYPES = {
    "Path", "pathlib.Path",
    "PosixPath", "pathlib.PosixPath",
    "WindowsPath", "pathlib.WindowsPath",
}
PATH_RETURNING_METHODS = {
    "absolute", "expanduser", "joinpath", "readlink", "relative_to", "resolve",
    "with_name", "with_segments", "with_stem", "with_suffix",
}
PATH_ITERATOR_METHODS = {"glob", "iterdir", "rglob"}
PATH_ITERATOR_MATERIALIZERS = {"frozenset", "iter", "list", "reversed", "set", "sorted", "tuple"}
PATH_CLASS_RETURNING_METHODS = {"cwd", "home", "from_uri"}
PATH_ALWAYS_MUTATION_METHODS = {"lchmod", "replace"}
WRITE_MODE_MARKERS = frozenset("wax+")
MUTATING_OS_OPEN_FLAGS = {
    "O_APPEND", "O_CREAT", "O_RDWR", "O_TMPFILE", "O_TRUNC", "O_WRONLY",
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


def literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
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


def call_argument(node: ast.Call, index: int, keyword_name: str) -> ast.AST | None:
    result: ast.AST | None = node.args[index] if len(node.args) > index else None
    for keyword in node.keywords:
        if keyword.arg == keyword_name:
            result = keyword.value
    return result


def os_open_flag_terms(
    node: ast.AST | None,
    modules: dict[str, str],
    symbols: dict[str, str],
) -> tuple[set[str], bool]:
    if node is None:
        return set(), False
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return set(), node.value == 0
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, left_static = os_open_flag_terms(node.left, modules, symbols)
        right, right_static = os_open_flag_terms(node.right, modules, symbols)
        return left | right, left_static and right_static
    resolved = resolved_name(node, modules, symbols)
    if resolved and resolved.startswith("os.O_"):
        return {resolved.rsplit(".", 1)[-1]}, True
    return set(), False


def annotation_mentions_path(
    node: ast.AST | None,
    modules: dict[str, str],
    symbols: dict[str, str],
) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            parsed = ast.parse(node.value, mode="eval").body
        except SyntaxError:
            return False
        return annotation_mentions_path(parsed, modules, symbols)
    resolved = resolved_name(node, modules, symbols)
    if resolved in CONCRETE_PATH_TYPES:
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
    """Resolve concrete pathlib receivers without conflating same-named string/object methods."""

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
        self.global_path_iters: set[str] = set()
        self.scopes: list[set[str]] = []
        self.iter_scopes: list[set[str]] = []
        self.violations: list[str] = []

    @property
    def paths(self) -> set[str]:
        return self.scopes[-1] if self.scopes else self.global_paths

    @property
    def path_iters(self) -> set[str]:
        return self.iter_scopes[-1] if self.iter_scopes else self.global_path_iters

    def report(self, node: ast.AST, message: str) -> None:
        self.violations.append(f"line {getattr(node, 'lineno', '?')}: {message}")

    def is_path_type_expr(self, node: ast.AST) -> bool:
        return resolved_name(node, self.modules, self.symbols) in CONCRETE_PATH_TYPES

    def is_path_expr(self, node: ast.AST) -> bool:
        if self.is_path_type_expr(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.paths
        if isinstance(node, ast.Call):
            name = resolved_name(node.func, self.modules, self.symbols)
            if name in CONCRETE_PATH_TYPES:
                return True
            if isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr in PATH_CLASS_RETURNING_METHODS
                    and self.is_path_type_expr(node.func.value)
                ):
                    return True
                if node.func.attr in PATH_RETURNING_METHODS:
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

    def is_path_iter_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.path_iters
        if not isinstance(node, ast.Call):
            return False
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in PATH_ITERATOR_METHODS
            and self.is_path_expr(node.func.value)
        ):
            return True
        name = resolved_name(node.func, self.modules, self.symbols)
        return (
            name in PATH_ITERATOR_MATERIALIZERS
            and len(node.args) == 1
            and self.is_path_iter_expr(node.args[0])
        )

    def bind_target(self, target: ast.AST, is_path: bool) -> None:
        if isinstance(target, ast.Name):
            if is_path:
                self.paths.add(target.id)
            else:
                self.paths.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind_target(item, False)

    def bind_iter_target(self, target: ast.AST, is_path_iter: bool) -> None:
        if isinstance(target, ast.Name):
            if is_path_iter:
                self.path_iters.add(target.id)
            else:
                self.path_iters.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind_iter_target(item, False)

    def visit_Module(self, node: ast.Module) -> None:
        changed = True
        while changed:
            before_paths = set(self.global_paths)
            before_iters = set(self.global_path_iters)
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    is_path = self.is_path_expr(statement.value)
                    is_path_iter = self.is_path_iter_expr(statement.value)
                    for target in statement.targets:
                        if isinstance(target, ast.Name) and is_path:
                            self.global_paths.add(target.id)
                        if isinstance(target, ast.Name) and is_path_iter:
                            self.global_path_iters.add(target.id)
                elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    is_path = annotation_mentions_path(statement.annotation, self.modules, self.symbols)
                    is_path_iter = False
                    if statement.value is not None:
                        is_path = is_path or self.is_path_expr(statement.value)
                        is_path_iter = self.is_path_iter_expr(statement.value)
                    if is_path:
                        self.global_paths.add(statement.target.id)
                    if is_path_iter:
                        self.global_path_iters.add(statement.target.id)
            changed = before_paths != self.global_paths or before_iters != self.global_path_iters

        for statement in node.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        local = set(self.global_paths)
        local_iters = set(self.global_path_iters)
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if annotation_mentions_path(arg.annotation, self.modules, self.symbols):
                local.add(arg.arg)
        if node.args.vararg and annotation_mentions_path(node.args.vararg.annotation, self.modules, self.symbols):
            local.add(node.args.vararg.arg)
        if node.args.kwarg and annotation_mentions_path(node.args.kwarg.annotation, self.modules, self.symbols):
            local.add(node.args.kwarg.arg)
        self.scopes.append(local)
        self.iter_scopes.append(local_iters)
        for statement in node.body:
            self.visit(statement)
        self.iter_scopes.pop()
        self.scopes.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        is_path = self.is_path_expr(node.value)
        is_path_iter = self.is_path_iter_expr(node.value)
        for target in node.targets:
            self.bind_target(target, is_path)
            self.bind_iter_target(target, is_path_iter)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        is_path = annotation_mentions_path(node.annotation, self.modules, self.symbols)
        is_path_iter = False
        if node.value is not None:
            is_path = is_path or self.is_path_expr(node.value)
            is_path_iter = self.is_path_iter_expr(node.value)
        self.bind_target(node.target, is_path)
        self.bind_iter_target(node.target, is_path_iter)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self.bind_target(node.target, self.is_path_iter_expr(node.iter))
        self.bind_iter_target(node.target, False)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr in PATH_ALWAYS_MUTATION_METHODS:
            if self.is_path_expr(node.func.value):
                self.report(
                    node,
                    f"pathlib concrete-path {node.func.attr}() filesystem mutation is forbidden in validator production code",
                )
        if isinstance(node.func, ast.Attribute) and node.func.attr == "open" and self.is_path_expr(node.func.value):
            mode_index = 1 if self.is_path_type_expr(node.func.value) else 0
            mode_node = call_argument(node, mode_index, "mode")
            mode = literal_string(mode_node) if mode_node is not None else "r"
            if mode is None:
                self.report(node, "dynamic pathlib concrete-path open() mode is forbidden in validators")
            elif any(marker in mode for marker in WRITE_MODE_MARKERS):
                self.report(node, f"write-capable pathlib concrete-path open() is forbidden in validators: {mode!r}")
        call_name = resolved_name(node.func, self.modules, self.symbols)
        if call_name == "getattr" and len(node.args) >= 2:
            attribute = (
                node.args[1].value
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                else None
            )
            if attribute in PATH_ALWAYS_MUTATION_METHODS and self.is_path_expr(node.args[0]):
                self.report(
                    node,
                    f"reflective pathlib concrete-path {attribute} lookup is forbidden in validator production code",
                )
            if attribute == "open" and self.is_path_expr(node.args[0]):
                self.report(node, "reflective pathlib concrete-path open lookup is forbidden in validators")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in PATH_ALWAYS_MUTATION_METHODS and self.is_path_expr(node.value):
            if not direct_call_target(node, self.parents):
                self.report(
                    node,
                    f"pathlib concrete-path {node.attr} bound method must not be aliased in validators",
                )
        if node.attr == "open" and self.is_path_expr(node.value) and not direct_call_target(node, self.parents):
            self.report(node, "pathlib concrete-path open bound method must not be aliased in validators")
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
    validator = is_validator_path(path)

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
        if validator and call_name in VALIDATOR_ALWAYS_FORBIDDEN_CALLABLES:
            violations.append(
                f"line {node.lineno}: validator filesystem mutation callable is forbidden: {call_name}()"
            )
        if validator and call_name in {"io.open", "os.fdopen"}:
            mode_node = call_argument(node, 1, "mode")
            mode = literal_string(mode_node) if mode_node is not None else "r"
            if mode is None:
                violations.append(f"line {node.lineno}: dynamic {call_name} mode is forbidden in validators")
            elif any(marker in mode for marker in WRITE_MODE_MARKERS):
                violations.append(
                    f"line {node.lineno}: write-capable {call_name} mode is forbidden in validators: {mode!r}"
                )
        if validator and call_name == "os.open":
            flags_node = call_argument(node, 1, "flags")
            flag_terms, static = os_open_flag_terms(flags_node, modules, symbols)
            if not static:
                violations.append(f"line {node.lineno}: dynamic os.open flags are forbidden in validators")
            elif flag_terms & MUTATING_OS_OPEN_FLAGS:
                violations.append(
                    f"line {node.lineno}: mutating os.open flags are forbidden in validators: "
                    f"{sorted(flag_terms & MUTATING_OS_OPEN_FLAGS)}"
                )
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
            "from pathlib import PosixPath\ndef f():\n    PosixPath('a').replace('b')\n",
        ),
        "direct PosixPath.replace fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import WindowsPath\ndef f(p: WindowsPath):\n    p.replace('b')\n",
        ),
        "annotated WindowsPath.replace fixture must fail without platform instantiation",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import PosixPath\ndef f(p: 'PosixPath | None'):\n    if p is not None:\n        p.replace('b')\n",
        ),
        "quoted concrete-path annotation fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f():\n    Path.cwd().replace('b')\n",
        ),
        "Path.cwd concrete factory fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f():\n    Path.home().open('w')\n",
        ),
        "Path.home write-open fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f():\n    Path.from_uri('file:///tmp/a').replace('b')\n",
        ),
        "Path.from_uri concrete factory fixture must fail",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return p.readlink()\n",
        ),
        "read-only Path.readlink fixture must pass",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    p.readlink().replace('b')\n",
        ),
        "Path.readlink derived-path replace fixture must fail",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return p.with_segments('a', 'b')\n",
        ),
        "read-only Path.with_segments fixture must pass",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    p.with_segments('a').replace('b')\n",
        ),
        "Path.with_segments derived-path replace fixture must fail",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for child in p.iterdir():\n        child.read_text()\n",
        ),
        "read-only Path.iterdir loop fixture must pass",
    )
    for method, call in (("iterdir", "p.iterdir()"), ("glob", "p.glob('*.txt')"), ("rglob", "p.rglob('*.txt')")):
        require(
            inspect_source(
                validator,
                f"from pathlib import Path\ndef f(p: Path):\n    for child in {call}:\n        child.replace('b')\n",
            ),
            f"Path.{method} yielded-path replace fixture must fail",
        )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = p.iterdir()\n    for child in children:\n        child.read_text()\n",
        ),
        "read-only aliased Path iterator loop fixture must pass",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = p.iterdir()\n    for child in children:\n        child.replace('b')\n",
        ),
        "aliased Path iterator yielded-path replace fixture must fail",
    )
    for wrapper, call in (
        ("iter", "iter(p.iterdir())"),
        ("list", "list(p.iterdir())"),
        ("tuple", "tuple(p.glob('*.txt'))"),
        ("set", "set(p.rglob('*.txt'))"),
        ("frozenset", "frozenset(p.iterdir())"),
        ("sorted", "sorted(p.glob('*.txt'))"),
        ("reversed", "reversed(list(p.iterdir()))"),
    ):
        require(
            inspect_source(
                validator,
                f"from pathlib import Path\ndef f(p: Path):\n    for child in {call}:\n        child.replace('b')\n",
            ),
            f"Path iterator {wrapper} materializer must preserve yielded concrete-path identity",
        )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = p.iterdir()\n    children = ['alpha']\n    for child in children:\n        child.replace('a', 'b')\n",
        ),
        "Path iterator alias rebound to a string collection must stop carrying concrete-path identity",
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
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    p.lchmod(0o600)\n",
        ),
        "Path.lchmod fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    opener = p.open\n    return opener('r')\n",
        ),
        "Path.open bound-method alias fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return p.open('w')\n",
        ),
        "write-capable Path.open fixture must fail",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return p.open('r')\n",
        ),
        "read-only Path.open fixture must pass",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    mover = Path.replace\n    return mover(p, 'b')\n",
        ),
        "Path class-method alias fixture must fail",
    )
    require(
        inspect_source(validator, "import os\ndef f(p):\n    os.chown(p, 1, 1)\n"),
        "direct os.chown fixture must fail",
    )
    require(
        inspect_source(validator, "import shutil\ndef f(a, b):\n    shutil.copystat(a, b)\n"),
        "direct shutil.copystat fixture must fail",
    )
    require(
        inspect_source(validator, "from os import utime as touch_time\ndef f(p):\n    touch_time(p)\n"),
        "aliased os.utime fixture must fail",
    )
    require(
        not inspect_source(
            validator,
            "import os\ndef f(p):\n    return os.open(p, os.O_RDONLY | os.O_CLOEXEC)\n",
        ),
        "read-only os.open fixture must pass",
    )
    require(
        inspect_source(
            validator,
            "import os\ndef f(p):\n    return os.open(p, os.O_RDONLY | os.O_CREAT)\n",
        ),
        "mutating os.open fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "import os\ndef f(p, flags):\n    return os.open(p, flags)\n",
        ),
        "dynamic os.open flags fixture must fail",
    )
    require(
        not inspect_source(
            validator,
            "import os\ndef f(fd):\n    return os.fdopen(fd, 'r')\n",
        ),
        "read-only os.fdopen fixture must pass",
    )
    require(
        inspect_source(
            validator,
            "import os\ndef f(fd):\n    return os.fdopen(fd, 'wb')\n",
        ),
        "write-capable os.fdopen fixture must fail",
    )
    require(
        inspect_source(
            validator,
            "import io\ndef f(p, mode):\n    return io.open(p, mode)\n",
        ),
        "dynamic io.open mode fixture must fail",
    )
    require(
        not inspect_source(
            Path("generate-fixture.py"),
            "from pathlib import Path\nimport os\ndef f():\n    Path('a').replace('b')\n    os.chown('x', 1, 1)\n",
        ),
        "transformer/generator direct filesystem mutation fixture must remain outside validator purity scope",
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
            "validator concrete pathlib/open/fd and unambiguous filesystem mutation surfaces are fail-closed"
        )
        return 0
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
