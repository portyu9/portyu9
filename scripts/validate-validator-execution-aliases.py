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
PATH_SHAPE_MATERIALIZERS = {"list", "tuple"}
PATH_CLASS_RETURNING_METHODS = {"cwd", "home", "from_uri"}
PATH_ALWAYS_MUTATION_METHODS = {"lchmod", "replace"}
PATH_NEXT_CALLABLES = {"next", "builtins.next"}
PATH_VALUE_MASK = 1
PATH_ITER_VALUE_MASK = 2
ReceiverShape = tuple[object, ...]
FlowState = tuple[set[str], set[str], dict[str, set[ReceiverShape]]]
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
        self.global_receiver_shapes: dict[str, set[ReceiverShape]] = {}
        self.scopes: list[set[str]] = []
        self.iter_scopes: list[set[str]] = []
        self.shape_scopes: list[dict[str, set[ReceiverShape]]] = []
        self.comprehension_namedexpr_targets: list[
            tuple[set[str], set[str], dict[str, set[ReceiverShape]]]
        ] = []
        self.comprehension_scope_states: list[
            tuple[set[str], set[str], dict[str, set[ReceiverShape]]]
        ] = []
        self.violations: list[str] = []

    @property
    def paths(self) -> set[str]:
        return self.scopes[-1] if self.scopes else self.global_paths

    @property
    def path_iters(self) -> set[str]:
        return self.iter_scopes[-1] if self.iter_scopes else self.global_path_iters

    @property
    def receiver_shapes(self) -> dict[str, set[ReceiverShape]]:
        return self.shape_scopes[-1] if self.shape_scopes else self.global_receiver_shapes

    @staticmethod
    def copy_shape_map(
        shape_map: dict[str, set[ReceiverShape]],
    ) -> dict[str, set[ReceiverShape]]:
        return {name: set(shapes) for name, shapes in shape_map.items()}

    @staticmethod
    def static_sequence_index(node: ast.AST) -> tuple[bool, int]:
        sign = 1
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            sign = -1 if isinstance(node.op, ast.USub) else 1
            node = node.operand
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return True, sign * int(node.value)
        return False, 0

    def structured_index_slots(self, node: ast.Subscript) -> set[object]:
        if isinstance(node.slice, ast.Slice):
            return set()
        shapes = self.structured_shapes(node.value)
        if not shapes:
            return set()
        static, index = self.static_sequence_index(node.slice)
        slots: set[object] = set()
        for shape in shapes:
            if not static:
                slots.update(shape)
                continue
            normalized = index if index >= 0 else len(shape) + index
            if 0 <= normalized < len(shape):
                slots.add(shape[normalized])
        return slots

    def report(self, node: ast.AST, message: str) -> None:
        self.violations.append(f"line {getattr(node, 'lineno', '?')}: {message}")

    def is_path_type_expr(self, node: ast.AST) -> bool:
        return resolved_name(node, self.modules, self.symbols) in CONCRETE_PATH_TYPES

    def is_path_expr(self, node: ast.AST) -> bool:
        if self.is_path_type_expr(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.paths
        if isinstance(node, ast.NamedExpr):
            return self.is_path_expr(node.value)
        if isinstance(node, ast.BoolOp):
            return any(self.is_path_expr(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self.is_path_expr(node.body) or self.is_path_expr(node.orelse)
        if isinstance(node, ast.Call):
            name = resolved_name(node.func, self.modules, self.symbols)
            if name in CONCRETE_PATH_TYPES:
                return True
            if name in PATH_NEXT_CALLABLES and 1 <= len(node.args) <= 2:
                if self.is_path_iter_expr(node.args[0]):
                    return True
                if len(node.args) == 2 and self.is_path_expr(node.args[1]):
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
            return False
        if isinstance(node, ast.Subscript):
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr == "parents"
                and not isinstance(node.slice, ast.Slice)
            ):
                return self.is_path_expr(node.value.value)
            return any(
                isinstance(slot, int) and slot & PATH_VALUE_MASK
                for slot in self.structured_index_slots(node)
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.is_path_expr(node.left)
        return False

    def is_path_iter_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.path_iters
        if isinstance(node, ast.NamedExpr):
            return self.is_path_iter_expr(node.value)
        if isinstance(node, ast.BoolOp):
            return any(self.is_path_iter_expr(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self.is_path_iter_expr(node.body) or self.is_path_iter_expr(node.orelse)
        if isinstance(node, ast.Attribute) and node.attr == "parents":
            return self.is_path_expr(node.value)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "parents"
            and isinstance(node.slice, ast.Slice)
        ):
            return self.is_path_expr(node.value.value)
        if isinstance(node, ast.Subscript):
            return any(
                isinstance(slot, int) and slot & PATH_ITER_VALUE_MASK
                for slot in self.structured_index_slots(node)
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for item in node.elts:
                if isinstance(item, ast.Starred):
                    if self.is_path_iter_expr(item.value):
                        return True
                elif self.is_path_expr(item):
                    return True
            return False
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is None:
                    if self.is_path_iter_expr(value):
                        return True
                elif self.is_path_expr(key):
                    return True
            return False
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self.comprehension_yields_path(node)
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

    def receiver_mask(self, node: ast.AST) -> int:
        mask = 0
        if self.is_path_expr(node):
            mask |= PATH_VALUE_MASK
        if self.is_path_iter_expr(node):
            mask |= PATH_ITER_VALUE_MASK
        return mask

    def structured_shapes(self, node: ast.AST) -> set[ReceiverShape]:
        if isinstance(node, ast.Name):
            return set(self.receiver_shapes.get(node.id, set()))
        if isinstance(node, ast.NamedExpr):
            return self.structured_shapes(node.value)
        if isinstance(node, ast.BoolOp):
            shapes: set[ReceiverShape] = set()
            for value in node.values:
                shapes.update(self.structured_shapes(value))
            return shapes
        if isinstance(node, ast.IfExp):
            return self.structured_shapes(node.body) | self.structured_shapes(node.orelse)
        if isinstance(node, ast.Subscript):
            return {
                slot
                for slot in self.structured_index_slots(node)
                if isinstance(slot, tuple)
            }
        if isinstance(node, ast.Call):
            name = resolved_name(node.func, self.modules, self.symbols)
            if name in PATH_SHAPE_MATERIALIZERS and len(node.args) == 1 and not node.keywords:
                return self.structured_shapes(node.args[0])
            return set()
        if not isinstance(node, (ast.Tuple, ast.List)):
            return set()
        if any(isinstance(item, ast.Starred) for item in node.elts):
            return set()

        shapes: set[ReceiverShape] = {()}
        for item in node.elts:
            nested = self.structured_shapes(item)
            slots: set[object] = set(nested) if nested else {self.receiver_mask(item)}
            shapes = {
                prefix + (slot,)
                for prefix in shapes
                for slot in slots
            }
        return shapes

    def iter_structured_shapes(self, node: ast.AST) -> set[ReceiverShape]:
        yielded: set[ReceiverShape] = set()
        for shape in self.structured_shapes(node):
            for slot in shape:
                if isinstance(slot, tuple):
                    yielded.add(slot)
        return yielded

    def comprehension_yields_path(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
    ) -> bool:
        before = self.flow_state()
        try:
            for generator in node.generators:
                yields_path = self.is_path_iter_expr(generator.iter)
                yielded_shapes = self.iter_structured_shapes(generator.iter)
                self.bind_target(generator.target, yields_path)
                self.bind_iter_target(generator.target, False)
                self.bind_structured_target(generator.target, yielded_shapes)
            yielded = node.key if isinstance(node, ast.DictComp) else node.elt
            return self.is_path_expr(yielded)
        finally:
            self.restore_flow_state(before)

    def bind_target(self, target: ast.AST, is_path: bool) -> None:
        if isinstance(target, ast.Name):
            if is_path:
                self.paths.add(target.id)
            else:
                self.paths.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind_target(item.value if isinstance(item, ast.Starred) else item, False)

    def bind_iter_target(self, target: ast.AST, is_path_iter: bool) -> None:
        if isinstance(target, ast.Name):
            if is_path_iter:
                self.path_iters.add(target.id)
            else:
                self.path_iters.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind_iter_target(item.value if isinstance(item, ast.Starred) else item, False)

    def clear_shape_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.receiver_shapes.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.clear_shape_target(item.value if isinstance(item, ast.Starred) else item)

    def bind_receiver_slots(self, target: ast.AST, slots: list[object]) -> None:
        self.clear_shape_target(target)
        self.bind_target(target, False)
        self.bind_iter_target(target, False)
        if isinstance(target, ast.Name):
            nested = {slot for slot in slots if isinstance(slot, tuple)}
            if nested:
                self.receiver_shapes[target.id] = nested
            if any(isinstance(slot, int) and slot & PATH_VALUE_MASK for slot in slots):
                self.paths.add(target.id)
            if any(isinstance(slot, int) and slot & PATH_ITER_VALUE_MASK for slot in slots):
                self.path_iters.add(target.id)
            return
        if not isinstance(target, (ast.Tuple, ast.List)):
            return
        if any(isinstance(item, ast.Starred) for item in target.elts):
            return
        matching = [
            slot
            for slot in slots
            if isinstance(slot, tuple) and len(slot) == len(target.elts)
        ]
        for index, item in enumerate(target.elts):
            self.bind_receiver_slots(item, [shape[index] for shape in matching])

    def bind_structured_target(
        self,
        target: ast.AST,
        shapes: set[ReceiverShape],
    ) -> None:
        self.clear_shape_target(target)
        if isinstance(target, ast.Name):
            if shapes:
                self.receiver_shapes[target.id] = set(shapes)
            return
        if not isinstance(target, (ast.Tuple, ast.List)):
            return
        if any(isinstance(item, ast.Starred) for item in target.elts):
            return
        matching = [shape for shape in shapes if len(shape) == len(target.elts)]
        for index, item in enumerate(target.elts):
            self.bind_receiver_slots(item, [shape[index] for shape in matching])

    def flow_state(self) -> FlowState:
        return (
            set(self.paths),
            set(self.path_iters),
            self.copy_shape_map(self.receiver_shapes),
        )

    def restore_flow_state(self, state: FlowState) -> None:
        paths, path_iters, receiver_shapes = state
        self.paths.clear()
        self.paths.update(paths)
        self.path_iters.clear()
        self.path_iters.update(path_iters)
        self.receiver_shapes.clear()
        self.receiver_shapes.update(self.copy_shape_map(receiver_shapes))

    @staticmethod
    def merge_flow_states(*states: FlowState) -> FlowState:
        paths: set[str] = set()
        path_iters: set[str] = set()
        receiver_shapes: dict[str, set[ReceiverShape]] = {}
        for state_paths, state_iters, state_shapes in states:
            paths.update(state_paths)
            path_iters.update(state_iters)
            for name, shapes in state_shapes.items():
                receiver_shapes.setdefault(name, set()).update(shapes)
        return paths, path_iters, receiver_shapes

    def visit_flow_block(self, statements: list[ast.stmt]) -> FlowState:
        observed = self.flow_state()
        for statement in statements:
            self.visit(statement)
            observed = self.merge_flow_states(observed, self.flow_state())
        return observed

    def dedupe_violations(self, start: int) -> None:
        seen: set[str] = set()
        unique: list[str] = []
        for violation in self.violations[start:]:
            if violation not in seen:
                seen.add(violation)
                unique.append(violation)
        self.violations[start:] = unique

    @staticmethod
    def match_pattern_names(pattern: ast.pattern) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(pattern):
            if isinstance(node, ast.MatchAs) and node.name is not None:
                names.add(node.name)
            elif isinstance(node, ast.MatchStar) and node.name is not None:
                names.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest is not None:
                names.add(node.rest)
        return names

    @staticmethod
    def match_pattern_subject_names(pattern: ast.pattern, whole_subject: bool = True) -> set[str]:
        names: set[str] = set()
        if isinstance(pattern, ast.MatchAs):
            if whole_subject and pattern.name is not None:
                names.add(pattern.name)
            if pattern.pattern is not None:
                names.update(PathMutationVisitor.match_pattern_subject_names(pattern.pattern, whole_subject))
        elif isinstance(pattern, ast.MatchOr):
            for item in pattern.patterns:
                names.update(PathMutationVisitor.match_pattern_subject_names(item, whole_subject))
        elif isinstance(pattern, ast.MatchSequence):
            for item in pattern.patterns:
                names.update(PathMutationVisitor.match_pattern_subject_names(item, False))
        elif isinstance(pattern, ast.MatchMapping):
            for item in pattern.patterns:
                names.update(PathMutationVisitor.match_pattern_subject_names(item, False))
        elif isinstance(pattern, ast.MatchClass):
            for item in (*pattern.patterns, *pattern.kwd_patterns):
                names.update(PathMutationVisitor.match_pattern_subject_names(item, False))
        return names

    @staticmethod
    def match_pattern_is_irrefutable(pattern: ast.pattern) -> bool:
        if isinstance(pattern, ast.MatchAs):
            return pattern.pattern is None or PathMutationVisitor.match_pattern_is_irrefutable(pattern.pattern)
        if isinstance(pattern, ast.MatchOr):
            return any(PathMutationVisitor.match_pattern_is_irrefutable(item) for item in pattern.patterns)
        return False

    def bind_match_pattern(
        self,
        pattern: ast.pattern,
        subject_is_path: bool,
        subject_is_path_iter: bool,
        subject_shapes: set[ReceiverShape],
    ) -> None:
        bound = self.match_pattern_names(pattern)
        whole_subject = self.match_pattern_subject_names(pattern)
        self.paths.difference_update(bound)
        self.path_iters.difference_update(bound)
        for name in bound:
            self.receiver_shapes.pop(name, None)
        if subject_is_path:
            self.paths.update(whole_subject)
        if subject_is_path_iter:
            self.path_iters.update(whole_subject)
        if subject_shapes:
            for name in whole_subject:
                self.receiver_shapes[name] = set(subject_shapes)

    def visit_Module(self, node: ast.Module) -> None:
        changed = True
        while changed:
            before_paths = set(self.global_paths)
            before_iters = set(self.global_path_iters)
            before_shapes = self.copy_shape_map(self.global_receiver_shapes)
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    is_path = self.is_path_expr(statement.value)
                    is_path_iter = self.is_path_iter_expr(statement.value)
                    shapes = self.structured_shapes(statement.value)
                    for target in statement.targets:
                        if isinstance(target, ast.Name) and is_path:
                            self.global_paths.add(target.id)
                        if isinstance(target, ast.Name) and is_path_iter:
                            self.global_path_iters.add(target.id)
                        if isinstance(target, ast.Name) and shapes:
                            self.global_receiver_shapes.setdefault(target.id, set()).update(shapes)
                elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    is_path = annotation_mentions_path(statement.annotation, self.modules, self.symbols)
                    is_path_iter = False
                    shapes: set[ReceiverShape] = set()
                    if statement.value is not None:
                        is_path = is_path or self.is_path_expr(statement.value)
                        is_path_iter = self.is_path_iter_expr(statement.value)
                        shapes = self.structured_shapes(statement.value)
                    if is_path:
                        self.global_paths.add(statement.target.id)
                    if is_path_iter:
                        self.global_path_iters.add(statement.target.id)
                    if shapes:
                        self.global_receiver_shapes.setdefault(statement.target.id, set()).update(shapes)
            changed = (
                before_paths != self.global_paths
                or before_iters != self.global_path_iters
                or before_shapes != self.global_receiver_shapes
            )

        for statement in node.body:
            self.visit(statement)

    @staticmethod
    def callable_parameters(arguments: ast.arguments) -> tuple[ast.arg, ...]:
        parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        if arguments.vararg is not None:
            parameters.append(arguments.vararg)
        if arguments.kwarg is not None:
            parameters.append(arguments.kwarg)
        return tuple(parameters)

    def callable_default_state(
        self,
        arguments: ast.arguments,
    ) -> tuple[set[str], set[str], dict[str, set[ReceiverShape]]]:
        default_paths: set[str] = set()
        default_iters: set[str] = set()
        default_shapes: dict[str, set[ReceiverShape]] = {}
        positional = [*arguments.posonlyargs, *arguments.args]
        positional_defaults = positional[len(positional) - len(arguments.defaults):]
        for parameter, default in zip(positional_defaults, arguments.defaults):
            self.visit(default)
            if self.is_path_expr(default):
                default_paths.add(parameter.arg)
            if self.is_path_iter_expr(default):
                default_iters.add(parameter.arg)
            shapes = self.structured_shapes(default)
            if shapes:
                default_shapes[parameter.arg] = shapes
        for parameter, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
            if default is None:
                continue
            self.visit(default)
            if self.is_path_expr(default):
                default_paths.add(parameter.arg)
            if self.is_path_iter_expr(default):
                default_iters.add(parameter.arg)
            shapes = self.structured_shapes(default)
            if shapes:
                default_shapes[parameter.arg] = shapes
        return default_paths, default_iters, default_shapes

    def visit_function_definition(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        default_paths, default_iters, default_shapes = self.callable_default_state(node.args)
        parameters = self.callable_parameters(node.args)
        for parameter in parameters:
            if parameter.annotation is not None:
                self.visit(parameter.annotation)
        if node.returns is not None:
            self.visit(node.returns)
        for type_param in getattr(node, "type_params", ()):
            self.visit(type_param)

        local = set(self.paths)
        local_iters = set(self.path_iters)
        local_shapes = self.copy_shape_map(self.receiver_shapes)
        parameter_names = {parameter.arg for parameter in parameters}
        local.difference_update(parameter_names)
        local_iters.difference_update(parameter_names)
        for name in parameter_names:
            local_shapes.pop(name, None)
        local.discard(node.name)
        local_iters.discard(node.name)
        local_shapes.pop(node.name, None)
        local.update(default_paths)
        local_iters.update(default_iters)
        local_shapes.update(self.copy_shape_map(default_shapes))
        for parameter in parameters:
            if annotation_mentions_path(parameter.annotation, self.modules, self.symbols):
                local.add(parameter.arg)

        saved_namedexpr_targets = self.comprehension_namedexpr_targets
        saved_comprehension_scopes = self.comprehension_scope_states
        self.comprehension_namedexpr_targets = []
        self.comprehension_scope_states = []
        self.scopes.append(local)
        self.iter_scopes.append(local_iters)
        self.shape_scopes.append(local_shapes)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.shape_scopes.pop()
            self.iter_scopes.pop()
            self.scopes.pop()
            self.comprehension_namedexpr_targets = saved_namedexpr_targets
            self.comprehension_scope_states = saved_comprehension_scopes

        self.paths.discard(node.name)
        self.path_iters.discard(node.name)
        self.receiver_shapes.pop(node.name, None)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.visit_function_definition(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_function_definition(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        default_paths, default_iters, default_shapes = self.callable_default_state(node.args)
        parameters = self.callable_parameters(node.args)
        local = set(self.paths)
        local_iters = set(self.path_iters)
        local_shapes = self.copy_shape_map(self.receiver_shapes)
        parameter_names = {parameter.arg for parameter in parameters}
        local.difference_update(parameter_names)
        local_iters.difference_update(parameter_names)
        for name in parameter_names:
            local_shapes.pop(name, None)
        local.update(default_paths)
        local_iters.update(default_iters)
        local_shapes.update(self.copy_shape_map(default_shapes))
        saved_namedexpr_targets = self.comprehension_namedexpr_targets
        saved_comprehension_scopes = self.comprehension_scope_states
        self.comprehension_namedexpr_targets = []
        self.comprehension_scope_states = []
        self.scopes.append(local)
        self.iter_scopes.append(local_iters)
        self.shape_scopes.append(local_shapes)
        try:
            self.visit(node.body)
        finally:
            self.shape_scopes.pop()
            self.iter_scopes.pop()
            self.scopes.pop()
            self.comprehension_namedexpr_targets = saved_namedexpr_targets
            self.comprehension_scope_states = saved_comprehension_scopes

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        is_path = self.is_path_expr(node.value)
        is_path_iter = self.is_path_iter_expr(node.value)
        shapes = self.structured_shapes(node.value)
        for target in node.targets:
            self.bind_target(target, is_path)
            self.bind_iter_target(target, is_path_iter)
            self.bind_structured_target(target, shapes)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        is_path = annotation_mentions_path(node.annotation, self.modules, self.symbols)
        is_path_iter = False
        shapes: set[ReceiverShape] = set()
        if node.value is not None:
            is_path = is_path or self.is_path_expr(node.value)
            is_path_iter = self.is_path_iter_expr(node.value)
            shapes = self.structured_shapes(node.value)
        self.bind_target(node.target, is_path)
        self.bind_iter_target(node.target, is_path_iter)
        self.bind_structured_target(node.target, shapes)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        is_path = self.is_path_expr(node.value)
        is_path_iter = self.is_path_iter_expr(node.value)
        shapes = self.structured_shapes(node.value)
        if self.comprehension_namedexpr_targets and isinstance(node.target, ast.Name):
            name = node.target.id
            target_paths, target_iters, target_shapes = self.comprehension_namedexpr_targets[-1]
            if is_path:
                target_paths.add(name)
            if is_path_iter:
                target_iters.add(name)
            if shapes:
                target_shapes.setdefault(name, set()).update(shapes)
            for paths, path_iters, receiver_shapes in self.comprehension_scope_states[:-1]:
                if is_path:
                    paths.add(name)
                if is_path_iter:
                    path_iters.add(name)
                if shapes:
                    receiver_shapes.setdefault(name, set()).update(shapes)
        self.bind_target(node.target, is_path)
        self.bind_iter_target(node.target, is_path_iter)
        self.bind_structured_target(node.target, shapes)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if not node.values:
            return
        self.visit(node.values[0])
        state = self.flow_state()
        for value in node.values[1:]:
            entry = state
            self.restore_flow_state(entry)
            self.visit(value)
            evaluated = self.flow_state()
            state = self.merge_flow_states(entry, evaluated)
        self.restore_flow_state(state)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        before = self.flow_state()
        self.restore_flow_state(before)
        self.visit(node.body)
        body_state = self.flow_state()
        self.restore_flow_state(before)
        self.visit(node.orelse)
        else_state = self.flow_state()
        self.restore_flow_state(self.merge_flow_states(body_state, else_state))

    def visit_Compare(self, node: ast.Compare) -> None:
        self.visit(node.left)
        if not node.comparators:
            return
        self.visit(node.comparators[0])
        state = self.flow_state()
        for comparator in node.comparators[1:]:
            entry = state
            self.restore_flow_state(entry)
            self.visit(comparator)
            evaluated = self.flow_state()
            state = self.merge_flow_states(entry, evaluated)
        self.restore_flow_state(state)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.visit(node.test)
        continuation = self.flow_state()
        if node.msg is not None:
            self.visit(node.msg)
            self.restore_flow_state(continuation)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = self.flow_state()
        for statement in node.body:
            self.visit(statement)
        body_state = self.flow_state()
        self.restore_flow_state(before)
        for statement in node.orelse:
            self.visit(statement)
        else_state = self.flow_state()
        self.restore_flow_state(self.merge_flow_states(body_state, else_state))

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        before = self.flow_state()
        yields_path = self.is_path_iter_expr(node.iter)
        yielded_shapes = self.iter_structured_shapes(node.iter)
        head = before
        violation_start = len(self.violations)
        while True:
            self.restore_flow_state(head)
            self.bind_target(node.target, yields_path)
            self.bind_iter_target(node.target, False)
            self.bind_structured_target(node.target, yielded_shapes)
            observed = self.merge_flow_states(self.flow_state(), self.visit_flow_block(node.body))
            next_head = self.merge_flow_states(head, before, observed)
            if next_head == head:
                break
            head = next_head
        self.restore_flow_state(head)
        self.restore_flow_state(self.visit_flow_block(node.orelse))
        self.dedupe_violations(violation_start)

    def visit_While(self, node: ast.While) -> None:
        before = self.flow_state()
        head = before
        violation_start = len(self.violations)
        while True:
            self.restore_flow_state(head)
            self.visit(node.test)
            observed = self.merge_flow_states(self.flow_state(), self.visit_flow_block(node.body))
            next_head = self.merge_flow_states(head, before, observed)
            if next_head == head:
                break
            head = next_head
        self.restore_flow_state(head)
        self.restore_flow_state(self.visit_flow_block(node.orelse))
        self.dedupe_violations(violation_start)

    def visit_try_like(self, node: ast.Try | ast.TryStar) -> None:
        violation_start = len(self.violations)
        before = self.flow_state()

        self.restore_flow_state(before)
        body_observed = self.visit_flow_block(node.body)
        body_end = self.flow_state()

        self.restore_flow_state(body_end)
        else_observed = self.visit_flow_block(node.orelse)
        normal_end = self.flow_state()

        handler_ends: list[FlowState] = []
        handler_observed: list[FlowState] = []
        for handler in node.handlers:
            self.restore_flow_state(body_observed)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name is not None:
                self.paths.discard(handler.name)
                self.path_iters.discard(handler.name)
                self.receiver_shapes.pop(handler.name, None)
            handler_observed.append(self.visit_flow_block(handler.body))
            if handler.name is not None:
                self.paths.discard(handler.name)
                self.path_iters.discard(handler.name)
                self.receiver_shapes.pop(handler.name, None)
            handler_ends.append(self.flow_state())

        continuation = self.merge_flow_states(normal_end, *handler_ends)
        if node.finalbody:
            final_entry = self.merge_flow_states(
                body_observed,
                else_observed,
                continuation,
                *handler_observed,
            )
            self.restore_flow_state(final_entry)
            self.visit_flow_block(node.finalbody)

            self.restore_flow_state(continuation)
            self.visit_flow_block(node.finalbody)
            continuation = self.flow_state()

        self.restore_flow_state(continuation)
        self.dedupe_violations(violation_start)

    def visit_Try(self, node: ast.Try) -> None:
        self.visit_try_like(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.visit_try_like(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        subject_is_path = self.is_path_expr(node.subject)
        subject_is_path_iter = self.is_path_iter_expr(node.subject)
        subject_shapes = self.structured_shapes(node.subject)
        fallthrough: FlowState | None = self.flow_state()
        completed: list[FlowState] = []

        for case in node.cases:
            if fallthrough is None:
                break
            entry = fallthrough
            self.restore_flow_state(entry)
            self.bind_match_pattern(
                case.pattern,
                subject_is_path,
                subject_is_path_iter,
                subject_shapes,
            )
            if case.guard is not None:
                self.visit(case.guard)
            guarded = self.flow_state()
            self.visit_flow_block(case.body)
            completed.append(self.flow_state())

            irrefutable = self.match_pattern_is_irrefutable(case.pattern)
            if case.guard is not None:
                fallthrough = guarded if irrefutable else self.merge_flow_states(entry, guarded)
            elif irrefutable:
                fallthrough = None
            else:
                fallthrough = entry

        if fallthrough is not None:
            completed.append(fallthrough)
        self.restore_flow_state(self.merge_flow_states(*completed))

    def visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        yielded_nodes: tuple[ast.AST, ...],
    ) -> None:
        namedexpr_target = (
            self.comprehension_namedexpr_targets[-1]
            if self.comprehension_namedexpr_targets
            else (self.paths, self.path_iters, self.receiver_shapes)
        )
        local_paths = set(self.paths)
        local_iters = set(self.path_iters)
        local_shapes = self.copy_shape_map(self.receiver_shapes)
        self.scopes.append(local_paths)
        self.iter_scopes.append(local_iters)
        self.shape_scopes.append(local_shapes)
        self.comprehension_namedexpr_targets.append(namedexpr_target)
        self.comprehension_scope_states.append((local_paths, local_iters, local_shapes))
        try:
            for generator in node.generators:
                self.visit(generator.iter)
                yields_path = self.is_path_iter_expr(generator.iter)
                yielded_shapes = self.iter_structured_shapes(generator.iter)
                self.bind_target(generator.target, yields_path)
                self.bind_iter_target(generator.target, False)
                self.bind_structured_target(generator.target, yielded_shapes)
                for condition in generator.ifs:
                    self.visit(condition)
            for yielded in yielded_nodes:
                self.visit(yielded)
        finally:
            self.comprehension_scope_states.pop()
            self.comprehension_namedexpr_targets.pop()
            self.shape_scopes.pop()
            self.iter_scopes.pop()
            self.scopes.pop()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.visit_comprehension(node, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.visit_comprehension(node, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self.visit_comprehension(node, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.visit_comprehension(node, (node.key, node.value))

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
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for child in [p]:\n        child.replace('b')\n",
        ),
        "Path-valued list literal must preserve yielded concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for child in ('alpha', p):\n        child.replace('b')\n",
        ),
        "mixed tuple literal with a Path arm must preserve possible concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for child in {p}:\n        child.replace('b')\n",
        ),
        "Path-valued set literal must preserve yielded concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = [p]\n    for child in children:\n        child.replace('b')\n",
        ),
        "aliased Path-valued literal collection must preserve yielded concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = [*p.iterdir()]\n    for child in children:\n        child.replace('b')\n",
        ),
        "starred Path iterator expansion must preserve yielded concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for child in {p: 'value'}:\n        child.replace('b')\n",
        ),
        "Path-valued dict key must preserve normal dict-iteration identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    original = {p: 1}\n    copied = {**original}\n    for child in copied:\n        child.replace('b')\n",
        ),
        "dict unpacking must preserve possible concrete-Path key identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return [child.replace('b') for child in [p]]\n",
        ),
        "comprehension over a Path-valued literal must bind a concrete Path target",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    next(iter([p])).replace('b')\n",
        ),
        "next(iter(Path-valued literal)) must preserve concrete-Path extraction identity",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for name in {'alpha': p}:\n        name.replace('a', 'b')\n",
        ),
        "Path-valued dict values must not taint ordinary key iteration",
    )
    require(
        not inspect_source(
            validator,
            "def f():\n    for name in ['alpha', 'beta']:\n        name.replace('a', 'b')\n",
        ),
        "all-string literal collections must remain ordinary string replacement",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for child in [p]:\n        child.read_text()\n",
        ),
        "read-only Path literal iteration must remain valid",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for ancestor in p.parents:\n        ancestor.replace('b')\n",
        ),
        "Path.parents sequence iteration must preserve concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    ancestors = p.parents\n    for ancestor in ancestors:\n        ancestor.replace('b')\n",
        ),
        "aliased Path.parents sequence must preserve yielded concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    p.parents[0].replace('b')\n",
        ),
        "Path.parents scalar index must remain a concrete Path",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    p.parents[-1].replace('b')\n",
        ),
        "Path.parents negative scalar index must remain a concrete Path",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for ancestor in p.parents[:2]:\n        ancestor.replace('b')\n",
        ),
        "Path.parents slice must preserve Path-yielding tuple identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    ancestors = p.parents[1:]\n    for ancestor in ancestors:\n        ancestor.replace('b')\n",
        ),
        "aliased Path.parents slice must preserve Path-yielding tuple identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    next(iter(p.parents)).replace('b')\n",
        ),
        "next(iter(Path.parents)) must preserve concrete-Path extraction identity",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for ancestor in p.parents:\n        ancestor.read_text()\n",
        ),
        "read-only Path.parents iteration must remain valid",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    ancestors = p.parents\n    return ancestors.replace('a', 'b')\n",
        ),
        "Path.parents sequence object itself must not be misclassified as a concrete Path",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    ancestors = p.parents[:2]\n    return ancestors.replace('a', 'b')\n",
        ),
        "Path.parents slice tuple itself must not be misclassified as a concrete Path",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q, label = (p, 'alpha')\n    q.replace('b')\n",
        ),
        "fixed tuple destructuring must preserve a concrete-Path element",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    [q, label] = [p, 'alpha']\n    q.replace('b')\n",
        ),
        "fixed list destructuring must preserve a concrete-Path element",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = (p, 'alpha')\n    q, label = pair\n    q.replace('b')\n",
        ),
        "aliased fixed receiver shape must survive later destructuring",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    payload = ((p, 'alpha'), 'beta')\n    (q, label), other = payload\n    q.replace('b')\n",
        ),
        "nested fixed receiver shapes must bind recursively",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children, label = (p.iterdir(), 'alpha')\n    for child in children:\n        child.replace('b')\n",
        ),
        "structured binding must preserve Path-iterator leaves",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    for q, label in [(p, 'alpha')]:\n        q.replace('b')\n",
        ),
        "for-loop tuple target must receive a fixed structured element shape",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    rows = [(p, 'alpha')]\n    for q, label in rows:\n        q.replace('b')\n",
        ),
        "aliased iterable of fixed receiver shapes must bind a for-loop tuple target",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return [q.replace('b') for q, label in [(p, 'alpha')]]\n",
        ),
        "comprehension tuple targets must receive fixed structured element shapes",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = (p, 'alpha')\n    pair = ('beta', 'gamma')\n    q, label = pair\n    return q.replace('b', 'c')\n",
        ),
        "definite all-string structured reassignment must clear prior Path shape state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    pair = (p, 'alpha')\n    if flag:\n        pair = ('beta', 'gamma')\n    q, label = pair\n    q.replace('b')\n",
        ),
        "optional all-string structured reassignment must preserve an incoming Path shape alternative",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    pair = (p, 'alpha')\n    if flag:\n        pair = ('beta', 'gamma')\n    else:\n        pair = ('delta', 'epsilon')\n    q, label = pair\n    return q.replace('a', 'b')\n",
        ),
        "exhaustive all-string structured branches must clear concrete-Path shape state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    pair = ('alpha', 'beta')\n    while flag:\n        pair = (p, 'gamma')\n    q, label = pair\n    q.replace('b')\n",
        ),
        "loop-introduced structured Path state must survive the zero-or-more iteration join",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    pair = (p, 'alpha')\n    def inner():\n        q, label = pair\n        q.replace('b')\n    return inner\n",
        ),
        "nested callable closures must inherit fixed receiver-shape aliases",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    def inner(pair=(p, 'alpha')):\n        q, label = pair\n        q.replace('b')\n    return inner\n",
        ),
        "fixed receiver-shape callable defaults must preserve element identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = ('alpha', 'beta')\n    (pair := (p, 'gamma'))\n    q, label = pair\n    q.replace('b')\n",
        ),
        "assignment expressions must bind fixed receiver shapes",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = ('alpha', 'beta')\n    [(pair := (p, 'gamma')) for _ in [0]]\n    q, label = pair\n    q.replace('b')\n",
        ),
        "comprehension walrus fixed shapes must propagate into the containing callable",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = (p, 'alpha')\n    match pair:\n        case captured:\n            q, label = captured\n            q.replace('b')\n",
        ),
        "whole-subject match captures must preserve fixed receiver-shape aliases",
    )
    require(
        not inspect_source(
            validator,
            "def f():\n    q, label = ('alpha', 'beta')\n    return q.replace('a', 'b')\n",
        ),
        "ordinary all-string structured destructuring must remain valid",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    (p, 'alpha')[0].replace('b')\n",
        ),
        "direct fixed tuple index must preserve concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = (p, 'alpha')\n    pair[0].replace('b')\n",
        ),
        "aliased fixed tuple index must preserve concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = ('alpha', p)\n    pair[-1].replace('b')\n",
        ),
        "negative fixed tuple index must preserve concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    payload = ((p, 'alpha'), 'beta')\n    payload[0][0].replace('b')\n",
        ),
        "nested fixed index extraction must preserve concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = (p.iterdir(), 'alpha')\n    for child in pair[0]:\n        child.replace('b')\n",
        ),
        "fixed index extraction must preserve Path-iterator leaves",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, index):\n    pair = (p, 'alpha')\n    pair[index].replace('b')\n",
        ),
        "dynamic fixed-sequence index must conservatively preserve a Path alternative",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    pair = (p, 'alpha') if flag else ('beta', 'gamma')\n    pair[0].replace('b')\n",
        ),
        "fixed index extraction must preserve Path alternatives across conditional shapes",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    tuple((p, 'alpha'))[0].replace('b')\n",
        ),
        "fixed-shape tuple materialization must preserve indexed concrete-Path identity",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = (p, 'alpha')\n    return pair[1].replace('a', 'b')\n",
        ),
        "static string slot selection must not inherit sibling Path identity",
    )
    require(
        not inspect_source(
            validator,
            "def f(index):\n    pair = ('alpha', 'beta')\n    return pair[index].replace('a', 'b')\n",
        ),
        "dynamic indexing of an all-string fixed shape must remain ordinary string replacement",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    pair = (p, 'alpha')\n    return pair[0].read_text()\n",
        ),
        "read-only fixed index Path extraction must remain valid",
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
            "from pathlib import Path\ndef f(p: Path):\n    return [child.replace('b') for child in p.iterdir()]\n",
        ),
        "comprehension target from Path.iterdir must be treated as a concrete Path",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = [child for child in p.iterdir()]\n    for child in children:\n        child.replace('b')\n",
        ),
        "list comprehension yielding Paths must preserve Path-iterable identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = (child.resolve() for child in p.iterdir())\n    for child in children:\n        child.replace('b')\n",
        ),
        "generator expression yielding derived Paths must preserve Path-iterable identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = [grand for child in p.iterdir() for grand in child.iterdir()]\n    for grand in children:\n        grand.replace('b')\n",
        ),
        "nested comprehension generators must see prior concrete-Path targets",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return [child for child in p.iterdir() if child.replace('b')]\n",
        ),
        "comprehension filters must be visited with concrete-Path target state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = {child: child.name for child in p.iterdir()}\n    for child in children:\n        child.replace('b')\n",
        ),
        "dict comprehension Path keys must preserve Path-iterable identity",
    )
    require(
        not inspect_source(
            validator,
            "def f():\n    children = [name for name in ['alpha', 'beta']]\n    return [child.replace('a', 'b') for child in children]\n",
        ),
        "all-string comprehensions must remain ordinary string replacement",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    child = 'alpha'\n    [child.read_text() for child in p.iterdir()]\n    return child.replace('a', 'b')\n",
        ),
        "comprehension target Path identity must not leak into the enclosing scope",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return [child.read_text() for child in p.iterdir()]\n",
        ),
        "read-only Path comprehension must remain valid",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    next(p.iterdir()).replace('b')\n",
        ),
        "next() of a Path iterator must preserve concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    child = next(iter(p.iterdir()))\n    child.replace('b')\n",
        ),
        "next() of a wrapped Path iterator must bind a concrete Path",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    child = next((item.resolve() for item in p.iterdir()))\n    child.replace('b')\n",
        ),
        "next() of a Path-yielding generator expression must preserve concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "import builtins\nfrom pathlib import Path\ndef f(p: Path):\n    builtins.next(p.iterdir()).replace('b')\n",
        ),
        "builtins.next() of a Path iterator must preserve concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from builtins import next as advance\nfrom pathlib import Path\ndef f(p: Path):\n    advance(p.iterdir()).replace('b')\n",
        ),
        "imported builtins.next alias must preserve Path extraction identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    next(iter(()), p).replace('b')\n",
        ),
        "Path-valued next() default must conservatively preserve concrete-path identity",
    )
    require(
        not inspect_source(
            validator,
            "def f():\n    return next(iter(['alpha'])).replace('a', 'b')\n",
        ),
        "string next() extraction must remain ordinary string replacement",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    return next(p.iterdir()).read_text()\n",
        ),
        "read-only next() Path extraction must remain valid",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    def inner():\n        p.replace('b')\n    return inner\n",
        ),
        "nested function closure must inherit concrete-Path receiver state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    children = p.iterdir()\n    def inner():\n        for child in children:\n            child.replace('b')\n    return inner\n",
        ),
        "nested function closure must inherit Path-iterator receiver state",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    def inner(p):\n        return p.replace('a', 'b')\n    return inner\n",
        ),
        "nested unannotated parameter must shadow an enclosing concrete-Path name",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    def inner(q=p):\n        q.replace('b')\n    return inner\n",
        ),
        "Path-valued nested function default must preserve possible concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    def inner(children=p.iterdir()):\n        for child in children:\n            child.replace('b')\n    return inner\n",
        ),
        "Path-iterator nested function default must preserve yielded concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    def inner(q=p.replace('b')):\n        return q\n    return inner\n",
        ),
        "nested function defaults must be inspected in the enclosing receiver scope",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    @p.replace('b')\n    def inner():\n        return None\n    return inner\n",
        ),
        "nested function decorators must be inspected in the enclosing receiver scope",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    return lambda: p.replace('b')\n",
        ),
        "lambda closure must inherit concrete-Path receiver state",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    return lambda p: p.replace('a', 'b')\n",
        ),
        "lambda parameter must shadow an enclosing concrete-Path name",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    return lambda q=p: q.replace('b')\n",
        ),
        "Path-valued lambda default must preserve possible concrete-Path identity",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef outer(p: Path):\n    def inner():\n        return p.read_text()\n    return inner\n",
        ),
        "read-only nested concrete-Path closure must remain valid",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    (q := p).replace('b')\n",
        ),
        "Path-valued assignment expression result must retain concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    (q := p)\n    q.replace('b')\n",
        ),
        "assignment expression must bind a concrete Path for subsequent use",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    (children := p.iterdir())\n    for child in children:\n        child.replace('b')\n",
        ),
        "assignment expression must bind a Path-yielding iterator for subsequent use",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    (q := 'alpha')\n    return q.replace('a', 'b')\n",
        ),
        "definitely executed string assignment expression must clear concrete-Path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = p\n    flag and (q := 'alpha')\n    q.replace('b')\n",
        ),
        "short-circuit optional string walrus must not erase an incoming concrete-Path alternative",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = 'alpha'\n    flag or (q := p)\n    q.replace('b')\n",
        ),
        "short-circuit optional Path walrus must introduce a concrete-Path alternative",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = p\n    p if flag else (q := 'alpha')\n    q.replace('b')\n",
        ),
        "conditional-expression walrus arm must merge receiver state with the unselected arm",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, first):\n    q = p\n    first < 0 < (q := 'alpha')\n    q.replace('b')\n",
        ),
        "later chained-comparison walrus must preserve the short-circuit incoming Path alternative",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = 'alpha'\n    [(q := child) for child in p.iterdir()]\n    q.replace('b')\n",
        ),
        "comprehension walrus must bind into the containing callable scope",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    [(q := 'alpha') for _ in []]\n    q.replace('b')\n",
        ),
        "possibly empty comprehension walrus must not erase an incoming concrete-Path alternative",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = 'alpha'\n    [q.replace('b') for child in p.iterdir() if (q := child)]\n",
        ),
        "comprehension expressions after a Path walrus must see the assigned concrete Path",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = 'alpha'\n    [[None for _ in [0] if (q := p)] for _ in [0]]\n    q.replace('b')\n",
        ),
        "nested comprehension walrus must propagate a possible Path to the containing callable",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    fn = lambda: (q := 'alpha')\n    q.replace('b')\n",
        ),
        "lambda-local walrus must not mutate the enclosing receiver state",
    )
    require(
        not inspect_source(
            validator,
            "def f():\n    q = 'alpha'\n    (q := 'beta')\n    return q.replace('a', 'b')\n",
        ),
        "ordinary string assignment expression must remain ordinary string replacement",
    )
    require(
        not inspect_source(
            validator,
            "def f():\n    q = 'alpha'\n    [(q := name) for name in ['beta']]\n    return q.replace('a', 'b')\n",
        ),
        "ordinary string comprehension walrus must remain ordinary string replacement",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = p\n    if flag:\n        q = 'alpha'\n    q.replace('b')\n",
        ),
        "optional conditional reassignment must not erase concrete-path identity",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = p\n    if flag:\n        q = 'alpha'\n    else:\n        q = 'beta'\n    return q.replace('a', 'b')\n",
        ),
        "all conditional branches rebinding to strings must clear concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    children = p.iterdir()\n    if flag:\n        children = ['alpha']\n    for child in children:\n        child.replace('b')\n",
        ),
        "optional conditional iterator reassignment must not erase yielded concrete-path identity",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    children = p.iterdir()\n    if flag:\n        children = ['alpha']\n    else:\n        children = ['beta']\n    for child in children:\n        child.replace('a', 'b')\n",
        ),
        "all conditional branches rebinding iterator aliases to strings must clear yielded-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = p if flag else 'alpha'\n    q.replace('b')\n",
        ),
        "conditional expression with a concrete-path arm must retain concrete-path identity",
    )
    require(
        not inspect_source(
            validator,
            "def f(flag):\n    q = 'alpha' if flag else 'beta'\n    return q.replace('a', 'b')\n",
        ),
        "all-string conditional expression must remain ordinary string replacement",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    children = p.iterdir() if flag else ['alpha']\n    for child in children:\n        child.replace('b')\n",
        ),
        "conditional expression with a Path iterator arm must retain yielded concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    for _ in []:\n        q = 'alpha'\n    q.replace('b')\n",
        ),
        "zero-iteration for-loop reassignment must not erase concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = p\n    while flag:\n        q = 'alpha'\n    q.replace('b')\n",
        ),
        "zero-iteration while-loop reassignment must not erase concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = p.iterdir()\n    for _ in []:\n        children = ['alpha']\n    for child in children:\n        child.replace('b')\n",
        ),
        "zero-iteration loop reassignment must not erase Path-iterator identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = 'alpha'\n    while flag:\n        if isinstance(q, Path):\n            q.replace('b')\n        q = p\n",
        ),
        "second loop iteration must observe concrete-path state introduced by the prior iteration",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    children = ['alpha']\n    while flag:\n        for child in children:\n            child.replace('b')\n        children = p.iterdir()\n",
        ),
        "second loop iteration must observe Path-iterator state introduced by the prior iteration",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, flag):\n    q = 'alpha'\n    while flag:\n        q = p\n        break\n        q = 'beta'\n    q.replace('b')\n",
        ),
        "loop intermediate state before break must preserve concrete-path identity",
    )
    require(
        not inspect_source(
            validator,
            "def f(flag):\n    q = 'alpha'\n    while flag:\n        q = 'beta'\n    return q.replace('a', 'b')\n",
        ),
        "all-string loop state must remain ordinary string replacement",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    try:\n        int('not-an-int')\n        q = 'alpha'\n    except ValueError:\n        pass\n    q.replace('b')\n",
        ),
        "exception before try-body reassignment must preserve concrete-path handler state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    try:\n        int('not-an-int')\n        q = 'alpha'\n    except ValueError:\n        q.replace('b')\n",
        ),
        "try handler must observe concrete-path state possible at the exception point",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = p.iterdir()\n    try:\n        int('not-an-int')\n        children = ['alpha']\n    except ValueError:\n        pass\n    for child in children:\n        child.replace('b')\n",
        ),
        "exception before try-body reassignment must preserve Path-iterator handler state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = 'alpha'\n    try:\n        q = p\n    except Exception:\n        q = 'beta'\n    else:\n        q.replace('b')\n",
        ),
        "try else block must start from normal body completion rather than handler state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    try:\n        int('not-an-int')\n        q = 'alpha'\n    finally:\n        q.replace('b')\n",
        ),
        "finally block must observe concrete-path state from exceptional try-body exits",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    try:\n        q = 'alpha'\n    except Exception:\n        q = 'beta'\n    finally:\n        q = 'gamma'\n    return q.replace('a', 'b')\n",
        ),
        "unconditional finally string reassignment must clear concrete-path continuation state",
    )
    require(
        not inspect_source(
            validator,
            "def f():\n    q = 'alpha'\n    try:\n        q = 'beta'\n    except Exception:\n        q = 'gamma'\n    return q.replace('a', 'b')\n",
        ),
        "all-string try state must remain ordinary string replacement",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    try:\n        raise ExceptionGroup('x', [ValueError()])\n        q = 'alpha'\n    except* ValueError:\n        q.replace('b')\n",
        ),
        "except-star handler must conservatively preserve concrete-path exception-entry state",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, value):\n    q = p\n    match value:\n        case 0:\n            q = 'alpha'\n        case _:\n            pass\n    q.replace('b')\n",
        ),
        "mutually exclusive match cases must preserve a concrete-path alternative",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, value):\n    q = p\n    match value:\n        case 0:\n            q = 'alpha'\n        case _:\n            q = 'beta'\n    return q.replace('a', 'b')\n",
        ),
        "exhaustive all-string match cases must clear concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path, value):\n    q = p\n    match value:\n        case 0:\n            q = 'alpha'\n    q.replace('b')\n",
        ),
        "non-exhaustive match must retain unmatched incoming concrete-path state",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    match 'alpha':\n        case q:\n            return q.replace('a', 'b')\n",
        ),
        "whole-subject string capture must clear a prior concrete-path binding",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    match p:\n        case q:\n            q.replace('b')\n",
        ),
        "whole-subject capture must preserve concrete-path subject identity",
    )
    require(
        not inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = p\n    match ['alpha']:\n        case [q]:\n            return q.replace('a', 'b')\n",
        ),
        "nested pattern capture must not inherit whole-subject concrete-path identity",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    q = 'alpha'\n    match p:\n        case q if False:\n            pass\n        case _:\n            q.replace('b')\n",
        ),
        "guard-false match fallthrough must preserve successful Path capture binding",
    )
    require(
        inspect_source(
            validator,
            "from pathlib import Path\ndef f(p: Path):\n    children = p.iterdir()\n    match children:\n        case items:\n            for child in items:\n                child.replace('b')\n",
        ),
        "whole-subject match capture must preserve Path-iterator identity",
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
