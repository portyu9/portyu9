#!/usr/bin/env python3
"""Fail closed when validators or their reachable helper imports can mutate evidence.

Validator modules are observers. Production validation paths may read files, parse
contracts, perform bounded network reads, and fail, but they must not rewrite evidence
or launch arbitrary child processes. Explicit transformer/generator scripts own mutation.

The full body of every validator is inspected. In addition, every reachable local Python
helper import is inspected for *import-time* side effects, including module/class bodies,
decorators, and default expressions, while ordinary helper function bodies remain outside
that import-time rule until invoked by a validator. This closes the case where importing a
seemingly read-only helper could mutate files or launch a process before validation starts.

Self-tests may create isolated temporary fixtures only inside
``tempfile.TemporaryDirectory()`` scopes. Process execution is never exempt merely
because it occurs in a self-test. Two production subprocess boundaries are explicitly
reviewed: immutable action-tag resolution via ``git ls-remote --tags`` and the canonical
profile-evidence validation runner dispatching manifest-declared validator scripts.
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
PROCESS_EXECUTORS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system",
    "os.popen",
    "pty.spawn",
}
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


def literal_bool_keyword(node: ast.Call, name: str) -> bool | None:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, bool):
            return keyword.value.value
    return None


def list_prefix(node: ast.AST | None) -> tuple[str, ...]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return ()
    result: list[str] = []
    for item in node.elts:
        value = literal_string(item)
        if value is None:
            break
        result.append(value)
    return tuple(result)


def local_module_path(module: str) -> Path | None:
    """Resolve a top-level import name to one real scripts/*.py module when present."""
    root_name = module.split(".", 1)[0]
    if not root_name or root_name == Path(SELF).stem:
        return None
    candidate = SCRIPTS / f"{root_name}.py"
    if not candidate.is_file() or candidate.is_symlink():
        return None
    if candidate.absolute() != candidate.resolve(strict=True):
        return None
    return candidate


def local_imports(source: str, *, filename: str) -> set[Path]:
    """Return every local module named by an import anywhere in the source tree."""
    tree = ast.parse(source, filename=filename)
    result: set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                candidate = local_module_path(alias.name)
                if candidate is not None:
                    result.add(candidate)
        elif isinstance(node, ast.ImportFrom) and node.module:
            candidate = local_module_path(node.module)
            if candidate is not None:
                result.add(candidate)
    return result


def helper_import_closure(validators: list[Path]) -> list[Path]:
    """Derive the transitive local helper import closure reachable from validators."""
    validator_set = set(validators)
    pending: list[Path] = []
    for validator in validators:
        pending.extend(local_imports(validator.read_text(encoding="utf-8"), filename=str(validator)))

    observed: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in observed or path in validator_set or path.name == SELF:
            continue
        observed.add(path)
        source = path.read_text(encoding="utf-8")
        for imported in local_imports(source, filename=str(path)):
            if imported not in observed and imported not in validator_set:
                pending.append(imported)
    return sorted(observed)


class PurityVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.functions: list[str] = []
        self.temp_fixture_depth = 0
        self.violations: list[str] = []

    @property
    def in_self_test(self) -> bool:
        return any(name == "self_test" or name.startswith("self_test_") for name in self.functions)

    @property
    def current_function(self) -> str | None:
        return self.functions[-1] if self.functions else None

    def report(self, node: ast.AST, message: str, *, allow_temp_fixture: bool = False) -> None:
        if allow_temp_fixture and self.in_self_test and self.temp_fixture_depth > 0:
            return
        self.violations.append(f"{self.path.name}:{getattr(node, 'lineno', '?')}: {message}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_With(self, node: ast.With) -> None:
        temporary = any(
            dotted_name(item.context_expr.func) == "tempfile.TemporaryDirectory"
            for item in node.items
            if isinstance(item.context_expr, ast.Call)
        )
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
        if temporary and self.in_self_test:
            self.temp_fixture_depth += 1
            for statement in node.body:
                self.visit(statement)
            self.temp_fixture_depth -= 1
        else:
            for statement in node.body:
                self.visit(statement)

    def allowed_process(self, node: ast.Call, name: str) -> bool:
        # Action release provenance may resolve only exact public tag refs through a
        # non-shell, read-only `git ls-remote --tags` invocation.
        if (
            self.path.name == "validate-action-release-provenance.py"
            and self.current_function == "resolve_public_tag"
            and name == "subprocess.run"
            and node.args
            and list_prefix(node.args[0]) == ("git", "ls-remote", "--tags")
            and literal_bool_keyword(node, "check") is False
            and literal_bool_keyword(node, "shell") is not True
        ):
            return True

        # The canonical validation runner may execute only the manifest-resolved Python
        # validator command form `[sys.executable, str(script), *command_args]`.
        if (
            self.path.name == "validate-profile-evidence-boundary.py"
            and self.current_function == "main"
            and name == "subprocess.run"
            and node.args
            and isinstance(node.args[0], ast.List)
        ):
            command = node.args[0].elts
            prefix_ok = (
                len(command) == 3
                and dotted_name(command[0]) == "sys.executable"
                and isinstance(command[1], ast.Call)
                and dotted_name(command[1].func) == "str"
                and len(command[1].args) == 1
                and dotted_name(command[1].args[0]) == "script"
                and isinstance(command[2], ast.Starred)
                and dotted_name(command[2].value) == "command_args"
            )
            if prefix_ok and literal_bool_keyword(node, "check") is True and literal_bool_keyword(node, "shell") is not True:
                return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func) or ""
        leaf = name.rsplit(".", 1)[-1]

        if leaf in WRITE_METHODS:
            self.report(
                node,
                f"filesystem mutation method is forbidden outside isolated self-test temp fixtures: {leaf}()",
                allow_temp_fixture=True,
            )
        if leaf in MUTATOR_METHODS:
            self.report(
                node,
                f"transformer-style mutation call is forbidden outside isolated self-test temp fixtures: {leaf}()",
                allow_temp_fixture=True,
            )
        if name in {f"os.{item}" for item in OS_MUTATORS}:
            self.report(
                node,
                f"OS filesystem mutation is forbidden outside isolated self-test temp fixtures: {name}()",
                allow_temp_fixture=True,
            )
        if name in {f"shutil.{item}" for item in SHUTIL_MUTATORS}:
            self.report(
                node,
                f"shutil filesystem mutation is forbidden outside isolated self-test temp fixtures: {name}()",
                allow_temp_fixture=True,
            )

        if name == "open" or leaf == "open":
            mode_node: ast.AST | None = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode_node = keyword.value
            mode = literal_string(mode_node) if mode_node is not None else "r"
            if mode is None:
                self.report(node, "dynamic open() mode is forbidden in validators")
            elif any(marker in mode for marker in WRITE_MODE_MARKERS):
                self.report(
                    node,
                    f"write-capable open() mode is forbidden outside isolated self-test temp fixtures: {mode!r}",
                    allow_temp_fixture=True,
                )

        if name in PROCESS_EXECUTORS and not self.allowed_process(node, name):
            self.report(node, f"unreviewed process execution is forbidden in validators: {name}()")

        self.generic_visit(node)


class ImportTimePurityVisitor(PurityVisitor):
    """Inspect code that can execute while a helper module is being imported."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Function bodies are dormant at import time, but decorators/defaults execute.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if arg.annotation is not None:
                self.visit(arg.annotation)
        if node.args.vararg is not None and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)
        if node.returns is not None:
            self.visit(node.returns)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # The lambda body is dormant until the lambda is invoked.
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)


def inspect_source(path: Path, source: str) -> list[str]:
    tree = ast.parse(source, filename=str(path))
    visitor = PurityVisitor(path)
    visitor.visit(tree)
    return visitor.violations


def inspect_import_time_source(path: Path, source: str) -> list[str]:
    tree = ast.parse(source, filename=str(path))
    visitor = ImportTimePurityVisitor(path)
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
        inspect_source(fixture, "def self_test(p):\n    p.write_text('fixture')\n"),
        "self-test mutation outside a TemporaryDirectory must fail",
    )
    isolated = (
        "import tempfile\nfrom pathlib import Path\n"
        "def self_test():\n"
        "    with tempfile.TemporaryDirectory() as tmp:\n"
        "        Path(tmp, 'fixture').write_text('x')\n"
    )
    require(not inspect_source(fixture, isolated), "isolated TemporaryDirectory self-test mutation must pass")
    require(
        inspect_source(fixture, "def validate():\n    subprocess.run(['sh', '-c', 'touch x'])\n"),
        "arbitrary subprocess execution must fail",
    )
    require(
        inspect_source(fixture, "def self_test():\n    subprocess.run(['git', 'status'])\n"),
        "self-test process execution must not receive a blanket exemption",
    )
    release_fixture = Path("validate-action-release-provenance.py")
    release_source = (
        "import subprocess\n"
        "def resolve_public_tag():\n"
        "    subprocess.run(['git', 'ls-remote', '--tags', url, direct_ref, peeled_ref], check=False)\n"
    )
    require(not inspect_source(release_fixture, release_source), "reviewed git ls-remote provenance command must pass")
    require(
        inspect_source(release_fixture, release_source.replace("'ls-remote'", "'push'")),
        "action provenance process allowlist must reject a different git subcommand",
    )
    runner_fixture = Path("validate-profile-evidence-boundary.py")
    runner_source = (
        "import subprocess, sys\n"
        "def main():\n"
        "    subprocess.run([sys.executable, str(script), *command_args], check=True)\n"
    )
    require(not inspect_source(runner_fixture, runner_source), "canonical validator dispatch must pass")
    require(
        inspect_source(runner_fixture, runner_source.replace("check=True", "check=False")),
        "canonical validator dispatch must fail closed when check=True is removed",
    )

    helper = Path("helper.py")
    require(
        inspect_import_time_source(helper, "from pathlib import Path\nPath('x').write_text('x')\n"),
        "helper import-time filesystem mutation must fail",
    )
    require(
        inspect_import_time_source(helper, "import subprocess\nsubprocess.run(['git', 'status'])\n"),
        "helper import-time process execution must fail",
    )
    require(
        not inspect_import_time_source(helper, "def dormant(p):\n    p.write_text('x')\n"),
        "dormant helper function body must not be misclassified as import-time execution",
    )
    require(
        inspect_import_time_source(helper, "def configured(value=Path('x').write_text('x')):\n    return value\n"),
        "helper default expression executes at import time and must fail",
    )
    require(
        inspect_import_time_source(helper, "class Config:\n    marker = Path('x').write_text('x')\n"),
        "helper class body executes at import time and must fail",
    )
    print("Validator purity firewall self-test passed: validator bodies closed; helper import-time execution closed")


def main() -> int:
    try:
        self_test()
        paths = validator_paths()
        require(paths, "no validator modules discovered")
        helpers = helper_import_closure(paths)
        violations: list[str] = []
        for path in paths:
            violations.extend(inspect_source(path, path.read_text(encoding="utf-8")))
        for path in helpers:
            violations.extend(inspect_import_time_source(path, path.read_text(encoding="utf-8")))
        if violations:
            raise ValueError("validator purity violations:\n  " + "\n  ".join(violations))
        print(
            f"Validator purity passed: {len(paths)} validator modules are production read-only; "
            f"{len(helpers)} reachable local helper modules have mutation/process-free import-time execution; "
            "self-test mutation is temp-isolated, and process execution is closed to reviewed read-only boundaries"
        )
        return 0
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
