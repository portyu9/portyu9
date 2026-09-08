#!/usr/bin/env python3
"""Fail closed when validators or their reachable helper execution can mutate evidence.

Validator modules are observers. Production validation paths may read files, parse
contracts, perform bounded network reads, and fail, but they must not rewrite evidence
or launch arbitrary child processes. Explicit transformer/generator scripts own mutation.

Every validator body is inspected. Reachable local helper imports are inspected for
import-time side effects, and production calls into those helpers are followed through a
static local-function call graph and inspected recursively. Four legacy validators
dynamically execute exact repository modules whose filenames cannot be imported normally;
those dynamic targets and callable surfaces are closed here to an explicit reviewed
allowlist, their transitive import-time code is inspected, and every allowed delegated
function closure is proven read-only.

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

WRITE_METHODS = {
    "write_text", "write_bytes", "touch", "mkdir", "unlink", "rename", "rmdir",
    "chmod", "symlink_to", "hardlink_to",
}
MUTATOR_METHODS = {"apply"}
OS_MUTATORS = {
    "remove", "unlink", "rename", "replace", "mkdir", "makedirs", "rmdir",
    "removedirs", "chmod", "truncate",
}
SHUTIL_MUTATORS = {"copy", "copy2", "copyfile", "copytree", "move", "rmtree"}
PROCESS_EXECUTORS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
    "os.system", "os.popen", "pty.spawn",
}
DYNAMIC_CODE_EXECUTORS = {
    "exec", "eval", "compile", "__import__", "importlib.import_module",
    "runpy.run_module", "runpy.run_path",
}
WRITE_MODE_MARKERS = frozenset("wax+")

# Exact dynamic execution retained only at reviewed compatibility boundaries. Each alias
# is bound to one repository module and one exact callable surface. Target import-time
# closure and every delegated function body reachable from these calls are inspected.
REVIEWED_DYNAMIC_DELEGATES: dict[str, dict[str, tuple[str, frozenset[str]]]] = {
    "validate-portfolio-evidence-ledger.py": {
        "generator": (
            "generate-portfolio-evidence-ledger.py",
            frozenset({"fetch_json", "retry_delay_seconds"}),
        ),
    },
    "validate-profile-v4.py": {
        "legacy": (
            "validate-profile.py",
            frozenset({"fail", "safe_svg"}),
        ),
    },
    "validate-signal-field-v213.py": {
        "clarity": (
            "clarify-signal-field-evidence-window.py",
            frozenset({"attrs_of", "layout_of", "validate"}),
        ),
    },
    "validate-signal-field-v214.py": {
        "identifier": (
            "identify-signal-field-evidence.py",
            frozenset({"root_attrs", "validate_stamped", "fixture", "evidence_identity", "stamp_text"}),
        ),
        "presentation": (
            "polish-signal-field-evidence-v215.py",
            frozenset({"validate"}),
        ),
        "issues_balance": (
            "balance-signal-field-issues-label.py",
            frozenset({"validate"}),
        ),
    },
}
DYNAMIC_TARGET_SNIPPETS = {
    "validate-portfolio-evidence-ledger.py": (
        'GENERATOR = Path(__file__).with_name("generate-portfolio-evidence-ledger.py")',
    ),
    "validate-profile-v4.py": (
        'LEGACY_PATH = ROOT / "scripts/validate-profile.py"',
    ),
    "validate-signal-field-v213.py": (
        'CLARITY_SCRIPT = ROOT / "clarify-signal-field-evidence-window.py"',
    ),
    "validate-signal-field-v214.py": (
        'IDENTIFIER_PATH = ROOT / "scripts/identify-signal-field-evidence.py"',
        'PRESENTATION_PATH = ROOT / "scripts/polish-signal-field-evidence-v215.py"',
        'ISSUES_BALANCE_PATH = ROOT / "scripts/balance-signal-field-issues-label.py"',
    ),
}
REVIEWED_DYNAMIC_LOADERS = {
    ("validate-portfolio-evidence-ledger.py", "load_generator"),
    ("validate-profile-v4.py", "load_legacy"),
    ("validate-signal-field-v213.py", "load_clarity"),
    ("validate-signal-field-v214.py", "load_module"),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validator_paths() -> list[Path]:
    paths = {*SCRIPTS.glob("validate-*.py"), *SCRIPTS.glob("validate_*.py")}
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


def import_time_closure(roots: set[Path], *, excluded: set[Path] | None = None) -> list[Path]:
    excluded = excluded or set()
    pending = list(roots)
    observed: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in observed or path in excluded or path.name == SELF:
            continue
        require(path.is_file() and not path.is_symlink(), f"helper import target is missing or aliased: {path}")
        require(path.absolute() == path.resolve(strict=True), f"helper import target resolves through an alias: {path}")
        observed.add(path)
        source = path.read_text(encoding="utf-8")
        for imported in local_imports(source, filename=str(path)):
            if imported not in observed and imported not in excluded:
                pending.append(imported)
    return sorted(observed)


def helper_import_closure(validators: list[Path]) -> list[Path]:
    validator_set = set(validators)
    roots: set[Path] = set()
    for validator in validators:
        roots.update(local_imports(validator.read_text(encoding="utf-8"), filename=str(validator)))
    return import_time_closure(roots, excluded=validator_set)


def local_import_bindings(source: str, *, filename: str) -> tuple[dict[str, Path], dict[str, tuple[Path, str]]]:
    tree = ast.parse(source, filename=filename)
    modules: dict[str, Path] = {}
    symbols: dict[str, tuple[Path, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                candidate = local_module_path(alias.name)
                if candidate is not None:
                    modules[alias.asname or alias.name.split(".", 1)[0]] = candidate
        elif isinstance(node, ast.ImportFrom) and node.module:
            candidate = local_module_path(node.module)
            if candidate is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                symbols[alias.asname or alias.name] = (candidate, alias.name)
    return modules, symbols


def local_star_imports(source: str, *, filename: str) -> tuple[Path, ...]:
    tree = ast.parse(source, filename=filename)
    result: list[Path] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if not any(alias.name == "*" for alias in node.names):
            continue
        candidate = local_module_path(node.module)
        require(candidate is not None, f"{filename}: non-local star import is outside delegated purity resolution")
        result.append(candidate)
    return tuple(result)


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

    def allowed_dynamic_exec(self, name: str) -> bool:
        return (
            name.endswith(".exec_module")
            and self.current_function is not None
            and (self.path.name, self.current_function) in REVIEWED_DYNAMIC_LOADERS
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func) or ""
        leaf = name.rsplit(".", 1)[-1]
        if leaf in WRITE_METHODS:
            self.report(node, f"filesystem mutation method is forbidden outside isolated self-test temp fixtures: {leaf}()", allow_temp_fixture=True)
        if leaf in MUTATOR_METHODS:
            self.report(node, f"transformer-style mutation call is forbidden outside isolated self-test temp fixtures: {leaf}()", allow_temp_fixture=True)
        if name in {f"os.{item}" for item in OS_MUTATORS}:
            self.report(node, f"OS filesystem mutation is forbidden outside isolated self-test temp fixtures: {name}()", allow_temp_fixture=True)
        if name in {f"shutil.{item}" for item in SHUTIL_MUTATORS}:
            self.report(node, f"shutil filesystem mutation is forbidden outside isolated self-test temp fixtures: {name}()", allow_temp_fixture=True)
        if name == "open" or leaf == "open":
            mode_node: ast.AST | None = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode_node = keyword.value
            mode = literal_string(mode_node) if mode_node is not None else "r"
            if mode is None:
                self.report(node, "dynamic open() mode is forbidden in validators")
            elif any(marker in mode for marker in WRITE_MODE_MARKERS):
                self.report(node, f"write-capable open() mode is forbidden outside isolated self-test temp fixtures: {mode!r}", allow_temp_fixture=True)
        if name in PROCESS_EXECUTORS and not self.allowed_process(node, name):
            self.report(node, f"unreviewed process execution is forbidden in validators: {name}()")
        if name in DYNAMIC_CODE_EXECUTORS:
            self.report(node, f"dynamic code execution is forbidden in validators/helpers: {name}()")
        if leaf == "exec_module" and not self.allowed_dynamic_exec(name):
            self.report(node, f"unreviewed dynamic module execution is forbidden: {name}()")
        self.generic_visit(node)


class ImportTimePurityVisitor(PurityVisitor):
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
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


def top_level_functions(source: str, *, filename: str) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(source, filename=filename)
    return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def function_calls(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    local_functions: set[str],
    modules: dict[str, Path],
    symbols: dict[str, tuple[Path, str]],
) -> tuple[set[str], set[tuple[Path, str]]]:
    same_module: set[str] = set()
    imported: set[tuple[Path, str]] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = dotted_name(child.func) or ""
        if name in local_functions:
            same_module.add(name)
            continue
        if name in symbols:
            imported.add(symbols[name])
            continue
        parts = name.split(".")
        if len(parts) == 2 and parts[0] in modules:
            imported.add((modules[parts[0]], parts[1]))
    return same_module, imported


class ProductionHelperCallVisitor(ast.NodeVisitor):
    def __init__(self, modules: dict[str, Path], symbols: dict[str, tuple[Path, str]]) -> None:
        self.modules = modules
        self.symbols = symbols
        self.functions: list[str] = []
        self.calls: set[tuple[Path, str]] = set()

    @property
    def in_self_test(self) -> bool:
        return any(name == "self_test" or name.startswith("self_test_") for name in self.functions)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if not self.in_self_test:
            name = dotted_name(node.func) or ""
            if name in self.symbols:
                self.calls.add(self.symbols[name])
            else:
                parts = name.split(".")
                if len(parts) == 2 and parts[0] in self.modules:
                    self.calls.add((self.modules[parts[0]], parts[1]))
        self.generic_visit(node)


def production_helper_entrypoints(validators: list[Path]) -> set[tuple[Path, str]]:
    result: set[tuple[Path, str]] = set()
    for validator in validators:
        source = validator.read_text(encoding="utf-8")
        modules, symbols = local_import_bindings(source, filename=str(validator))
        visitor = ProductionHelperCallVisitor(modules, symbols)
        visitor.visit(ast.parse(source, filename=str(validator)))
        result.update(visitor.calls)
    return result


def inspect_function_closure(entrypoints: set[tuple[Path, str]]) -> tuple[list[str], set[tuple[Path, str]]]:
    pending = list(entrypoints)
    observed: set[tuple[Path, str]] = set()
    violations: list[str] = []
    cache: dict[Path, tuple[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef], dict[str, Path], dict[str, tuple[Path, str]]]] = {}

    while pending:
        path, function = pending.pop()
        key = (path, function)
        if key in observed:
            continue
        require(path.is_file() and not path.is_symlink(), f"delegated helper is missing or aliased: {path}")
        require(path.absolute() == path.resolve(strict=True), f"delegated helper resolves through an alias: {path}")
        if path not in cache:
            source = path.read_text(encoding="utf-8")
            functions = top_level_functions(source, filename=str(path))
            modules, symbols = local_import_bindings(source, filename=str(path))
            cache[path] = (source, functions, modules, symbols)
        source, functions, modules, symbols = cache[path]

        if function not in functions:
            matches: list[Path] = []
            for star_target in local_star_imports(source, filename=str(path)):
                target_source = star_target.read_text(encoding="utf-8")
                if function in top_level_functions(target_source, filename=str(star_target)):
                    matches.append(star_target)
            require(len(matches) == 1,
                    f"delegated helper function is missing or ambiguous: {path.name}:{function} star_matches={[item.name for item in matches]}")
            observed.add(key)
            pending.append((matches[0], function))
            continue

        node = functions[function]
        visitor = PurityVisitor(path)
        visitor.visit(node)
        violations.extend(visitor.violations)
        observed.add(key)
        same_module, imported = function_calls(node, local_functions=set(functions), modules=modules, symbols=symbols)
        pending.extend((path, name) for name in same_module if (path, name) not in observed)
        pending.extend(item for item in imported if item not in observed)
    return violations, observed


def dynamic_exec_inventory(validators: list[Path]) -> dict[str, int]:
    result: dict[str, int] = {}
    for validator in validators:
        tree = ast.parse(validator.read_text(encoding="utf-8"), filename=str(validator))
        count = sum(
            1 for node in ast.walk(tree)
            if isinstance(node, ast.Call) and (dotted_name(node.func) or "").endswith(".exec_module")
        )
        if count:
            result[validator.name] = count
    return result


def dynamic_alias_calls(source: str, aliases: set[str], *, filename: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {alias: set() for alias in aliases}
    tree = ast.parse(source, filename=filename)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        parts = (dotted_name(node.func) or "").split(".")
        if len(parts) == 2 and parts[0] in result:
            result[parts[0]].add(parts[1])
    return result


def validate_dynamic_delegates(validators: list[Path]) -> tuple[set[tuple[Path, str]], list[str], set[Path]]:
    inventory = dynamic_exec_inventory(validators)
    require(inventory == {name: 1 for name in REVIEWED_DYNAMIC_DELEGATES},
            f"dynamic validator execution inventory changed: {inventory!r}")
    by_name = {path.name: path for path in validators}
    entrypoints: set[tuple[Path, str]] = set()
    dynamic_targets: set[Path] = set()
    violations: list[str] = []
    for validator_name, delegates in REVIEWED_DYNAMIC_DELEGATES.items():
        require(validator_name in by_name, f"reviewed dynamic validator is missing: {validator_name}")
        validator = by_name[validator_name]
        source = validator.read_text(encoding="utf-8")
        for snippet in DYNAMIC_TARGET_SNIPPETS[validator_name]:
            require(source.count(snippet) == 1,
                    f"{validator_name}: reviewed dynamic target binding changed: {snippet}")
        observed_calls = dynamic_alias_calls(source, set(delegates), filename=str(validator))
        for alias, (target_name, expected_calls) in delegates.items():
            require(observed_calls[alias] == set(expected_calls),
                    f"{validator_name}: dynamic delegate call surface changed for {alias}: {sorted(observed_calls[alias])}")
            target = SCRIPTS / target_name
            require(target.is_file() and not target.is_symlink(),
                    f"{validator_name}: dynamic target is missing or aliased: {target_name}")
            require(target.absolute() == target.resolve(strict=True),
                    f"{validator_name}: dynamic target resolves through an alias: {target_name}")
            dynamic_targets.add(target)
            entrypoints.update((target, function) for function in expected_calls)

    # Dynamic execution imports the target and every local module imported by it, so the
    # same import-time purity proof must cover that transitive closure as static imports.
    for target in import_time_closure(dynamic_targets):
        violations.extend(inspect_import_time_source(target, target.read_text(encoding="utf-8")))
    return entrypoints, violations, dynamic_targets


def self_test() -> None:
    fixture = Path("validate-fixture.py")
    require(not inspect_source(fixture, "def validate(p):\n    return p.read_text()\n"), "read-only fixture must pass")
    require(not inspect_source(fixture, "def validate(s):\n    return s.replace('a', 'b')\n"), "string replace fixture must pass")
    require(inspect_source(fixture, "def validate(p):\n    p.write_text('x')\n"), "write_text fixture must fail")
    require(inspect_source(fixture, "def validate(p):\n    open(p, 'wb')\n"), "write-mode open fixture must fail")
    require(inspect_source(fixture, "def validate(m, p):\n    m.apply(p)\n"), "transformer apply fixture must fail")
    require(inspect_source(fixture, "def validate(a, b):\n    os.replace(a, b)\n"), "qualified os.replace fixture must fail")
    require(inspect_source(fixture, "def self_test(p):\n    p.write_text('fixture')\n"), "self-test mutation outside a TemporaryDirectory must fail")
    isolated = (
        "import tempfile\nfrom pathlib import Path\n"
        "def self_test():\n"
        "    with tempfile.TemporaryDirectory() as tmp:\n"
        "        Path(tmp, 'fixture').write_text('x')\n"
    )
    require(not inspect_source(fixture, isolated), "isolated TemporaryDirectory self-test mutation must pass")
    require(inspect_source(fixture, "def validate():\n    subprocess.run(['sh', '-c', 'touch x'])\n"), "arbitrary subprocess execution must fail")
    require(inspect_source(fixture, "def self_test():\n    subprocess.run(['git', 'status'])\n"), "self-test process execution must not receive a blanket exemption")
    require(inspect_source(fixture, "def validate():\n    exec('value = 1')\n"), "dynamic builtin execution must fail")
    require(inspect_source(fixture, "def validate(spec, module):\n    spec.loader.exec_module(module)\n"), "unreviewed dynamic module execution must fail")

    release_fixture = Path("validate-action-release-provenance.py")
    release_source = (
        "import subprocess\n"
        "def resolve_public_tag():\n"
        "    subprocess.run(['git', 'ls-remote', '--tags', url, direct_ref, peeled_ref], check=False)\n"
    )
    require(not inspect_source(release_fixture, release_source), "reviewed git ls-remote provenance command must pass")
    require(inspect_source(release_fixture, release_source.replace("'ls-remote'", "'push'")), "action provenance process allowlist must reject a different git subcommand")
    runner_fixture = Path("validate-profile-evidence-boundary.py")
    runner_source = (
        "import subprocess, sys\n"
        "def main():\n"
        "    subprocess.run([sys.executable, str(script), *command_args], check=True)\n"
    )
    require(not inspect_source(runner_fixture, runner_source), "canonical validator dispatch must pass")
    require(inspect_source(runner_fixture, runner_source.replace("check=True", "check=False")), "canonical validator dispatch must fail closed when check=True is removed")

    helper = Path("helper.py")
    require(inspect_import_time_source(helper, "from pathlib import Path\nPath('x').write_text('x')\n"), "helper import-time filesystem mutation must fail")
    require(inspect_import_time_source(helper, "import subprocess\nsubprocess.run(['git', 'status'])\n"), "helper import-time process execution must fail")
    require(not inspect_import_time_source(helper, "def dormant(p):\n    p.write_text('x')\n"), "dormant helper function body must not be misclassified as import-time execution")
    require(inspect_import_time_source(helper, "def configured(value=Path('x').write_text('x')):\n    return value\n"), "helper default expression executes at import time and must fail")
    require(inspect_import_time_source(helper, "class Config:\n    marker = Path('x').write_text('x')\n"), "helper class body executes at import time and must fail")

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        pure = tmp_root / "pure_helper.py"
        pure.write_text("def read(p):\n    return normalize(p.read_text())\ndef normalize(v):\n    return v.strip()\n", encoding="utf-8")
        violations, reached = inspect_function_closure({(pure, "read")})
        require(not violations and {(pure, "read"), (pure, "normalize")} <= reached,
                "read-only delegated helper closure must pass and follow same-module calls")

        mutating = tmp_root / "mutating_helper.py"
        mutating.write_text("def read(p):\n    return persist(p)\ndef persist(p):\n    p.write_text('x')\n", encoding="utf-8")
        violations, _ = inspect_function_closure({(mutating, "read")})
        require(any("write_text" in item for item in violations), "delegated helper filesystem mutation must be discovered transitively")

        process = tmp_root / "process_helper.py"
        process.write_text("import subprocess\ndef read():\n    return execute()\ndef execute():\n    subprocess.run(['git', 'status'])\n", encoding="utf-8")
        violations, _ = inspect_function_closure({(process, "read")})
        require(any("process execution" in item for item in violations), "delegated helper subprocess execution must be discovered transitively")

    print("Validator purity firewall self-test passed: validator bodies, dynamic code execution, helper import-time execution, and transitive delegated function bodies are closed")


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

        dynamic_entrypoints, dynamic_violations, dynamic_targets = validate_dynamic_delegates(paths)
        violations.extend(dynamic_violations)
        production_entrypoints = production_helper_entrypoints(paths)
        delegated_violations, reached = inspect_function_closure(production_entrypoints | dynamic_entrypoints)
        violations.extend(delegated_violations)

        if violations:
            raise ValueError("validator purity violations:\n  " + "\n  ".join(violations))
        print(
            f"Validator purity passed: {len(paths)} validator modules are production read-only; "
            f"{len(helpers)} statically imported local helpers and {len(dynamic_targets)} exact dynamic targets have transitive pure import-time execution; "
            f"{len(reached)} reachable delegated local functions are mutation/process-free; "
            "self-test mutation is temp-isolated, dynamic execution is closed to reviewed targets, and process execution is closed to reviewed read-only boundaries"
        )
        return 0
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
