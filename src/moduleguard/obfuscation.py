"""Conservative, scope-aware source obfuscation for protected modules."""

import ast
import hashlib
import keyword
from typing import Dict, Iterable, List, Optional, Set

from .errors import ProtectionError

_FUNCTION_SCOPES = {"function", "lambda", "comprehension"}
_DYNAMIC_LOCAL_CALLS = {"compile", "eval", "exec", "locals", "vars"}
_DYNAMIC_LOCAL_ATTRIBUTES = {"co_varnames", "f_locals"}
_RUNTIME_PREFIXES = ("__moduleguard_", "__MODULEGUARD_")


def _argument_names(arguments: ast.arguments) -> Set[str]:
    result = {argument.arg for argument in arguments.posonlyargs}
    result.update(argument.arg for argument in arguments.args)
    result.update(argument.arg for argument in arguments.kwonlyargs)
    if arguments.vararg is not None:
        result.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        result.add(arguments.kwarg.arg)
    return result


def _renamable_argument_names(arguments: ast.arguments) -> Set[str]:
    """Return parameters that do not need a stable keyword-call interface."""
    positional = arguments.posonlyargs + arguments.args
    defaulted = {
        argument.arg
        for argument in positional[len(positional) - len(arguments.defaults) :]
    }
    result = {argument.arg for argument in positional if argument.arg not in defaulted}
    if arguments.vararg is not None:
        result.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        result.add(arguments.kwarg.arg)
    return result


def _without_docstring(statements: List[ast.stmt]) -> List[ast.stmt]:
    """Remove a leading module, class, or function docstring."""
    if statements:
        first = statements[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            return statements[1:]
    return statements


def _target_names(target: ast.AST) -> Set[str]:
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }


class _BindingCollector(ast.NodeVisitor):
    """Collect bindings belonging directly to one lexical scope."""

    def __init__(self) -> None:
        self.bindings: Set[str] = set()
        self.declarations: Set[str] = set()
        self.preserved_bindings: Set[str] = set()
        self.globals: Set[str] = set()
        self.nonlocals: Set[str] = set()
        self.uses_dynamic_locals = False

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bindings.add(node.id)

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bindings.add(node.name)
        self.declarations.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bindings.add(node.name)
        self.declarations.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bindings.add(node.name)
        self.declarations.add(node.name)
        # Class bodies use dynamic LOAD_NAME lookup rather than normal function
        # local lookup. Preserve any enclosing local with the same spelling.
        self.preserved_bindings.update(
            child.id for child in ast.walk(node) if isinstance(child, ast.Name)
        )

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            binding = alias.asname or alias.name.split(".", 1)[0]
            self.bindings.add(binding)
            # Adding an alias to `import package.submodule` changes the object
            # bound by the statement, so keep its original root binding.
            if alias.asname is None and "." in alias.name:
                self.preserved_bindings.add(binding)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.bindings.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bindings.add(node.name)
        if node.type is not None:
            self.visit(node.type)
        for statement in node.body:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in _DYNAMIC_LOCAL_CALLS:
            self.uses_dynamic_locals = True
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _DYNAMIC_LOCAL_ATTRIBUTES:
            self.uses_dynamic_locals = True
        self.generic_visit(node)

    def _visit_comprehension(self, node: ast.AST) -> None:
        generators = getattr(node, "generators")
        for generator in generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(getattr(node, "elt"))

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension


class _Scope:
    def __init__(
        self,
        kind: str,
        bindings: Iterable[str] = (),
        parameters: Iterable[str] = (),
        globals_: Iterable[str] = (),
        nonlocals: Iterable[str] = (),
        mapping: Optional[Dict[str, str]] = None,
    ) -> None:
        self.kind = kind
        self.bindings = set(bindings)
        self.parameters = set(parameters)
        self.locals = self.bindings | self.parameters
        self.globals = set(globals_)
        self.nonlocals = set(nonlocals)
        self.mapping = mapping or {}


class _NameFactory:
    def __init__(self, source: str, used_names: Iterable[str]) -> None:
        self.seed = hashlib.sha256(source.encode("utf-8")).digest()
        self.used = set(used_names)
        self.counter = 0

    def create(self) -> str:
        while True:
            material = self.seed + self.counter.to_bytes(8, "big")
            digest = hashlib.sha256(material).digest()
            bits = "".join("{:08b}".format(byte) for byte in digest[:6])
            candidate = "I" + "".join("l" if bit == "1" else "I" for bit in bits)
            self.counter += 1
            if candidate not in self.used and not keyword.iskeyword(candidate):
                self.used.add(candidate)
                return candidate


class _ScopeAwareRenamer(ast.NodeTransformer):
    def __init__(self, source: str, tree: ast.Module) -> None:
        names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.arg):
                names.add(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.alias):
                names.add(node.asname or node.name.split(".", 1)[0])
        self.factory = _NameFactory(source, names)
        self.scopes: List[_Scope] = []

    def _mapping(self, candidates: Iterable[str]) -> Dict[str, str]:
        return {name: self.factory.create() for name in sorted(set(candidates))}

    def _collector(self, statements: Iterable[ast.stmt]) -> _BindingCollector:
        collector = _BindingCollector()
        for statement in statements:
            collector.visit(statement)
        return collector

    def _function_scope(self, node: ast.AST, kind: str = "function") -> _Scope:
        arguments = getattr(node, "args")
        parameters = _argument_names(arguments)
        renamable_parameters = _renamable_argument_names(arguments)
        if isinstance(node, ast.Lambda):
            collector = _BindingCollector()
            collector.visit(node.body)
        else:
            collector = self._collector(getattr(node, "body"))
        candidates = (
            (collector.bindings | renamable_parameters)
            - collector.globals
            - collector.nonlocals
            - collector.declarations
            - collector.preserved_bindings
        )
        candidates = {
            name
            for name in candidates
            if not (name.startswith("__") and name.endswith("__"))
        }
        mapping = {} if collector.uses_dynamic_locals else self._mapping(candidates)
        return _Scope(
            kind,
            bindings=collector.bindings,
            parameters=parameters,
            globals_=collector.globals,
            nonlocals=collector.nonlocals,
            mapping=mapping,
        )

    def _module_scope(self, node: ast.Module) -> _Scope:
        collector = self._collector(node.body)
        candidates = {
            name
            for name in collector.bindings
            if name.startswith(_RUNTIME_PREFIXES)
        }
        return _Scope("module", bindings=collector.bindings, mapping=self._mapping(candidates))

    def _class_scope(self, node: ast.ClassDef) -> _Scope:
        collector = self._collector(node.body)
        return _Scope(
            "class",
            bindings=collector.bindings,
            globals_=collector.globals,
            nonlocals=collector.nonlocals,
        )

    def _comprehension_scope(self, generators: Iterable[ast.comprehension]) -> _Scope:
        bindings: Set[str] = set()
        for generator in generators:
            bindings.update(_target_names(generator.target))
        return _Scope(
            "comprehension",
            bindings=bindings,
            mapping=self._mapping(bindings),
        )

    def _resolve(self, name: str, scopes: Optional[List[_Scope]] = None) -> str:
        active = self.scopes if scopes is None else scopes
        skip_class_scopes = bool(active and active[-1].kind in _FUNCTION_SCOPES)
        for scope in reversed(active):
            if scope.kind == "class" and skip_class_scopes:
                continue
            if name in scope.globals:
                return name
            if name in scope.nonlocals:
                continue
            if name in scope.locals:
                return scope.mapping.get(name, name)
        return name

    def visit_Module(self, node: ast.Module) -> ast.Module:
        node.body = _without_docstring(node.body)
        self.scopes.append(self._module_scope(node))
        node.body = [self.visit(statement) for statement in node.body]
        self.scopes.pop()
        return node

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = self._resolve(node.id)
        return node

    def visit_Global(self, node: ast.Global) -> ast.Global:
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.Nonlocal:
        node.names = [self._resolve(name, self.scopes[:-1]) for name in node.names]
        return node

    def _visit_arguments_in_parent(self, arguments: ast.arguments) -> None:
        for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs:
            if argument.annotation is not None:
                argument.annotation = self.visit(argument.annotation)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            arguments.vararg.annotation = self.visit(arguments.vararg.annotation)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            arguments.kwarg.annotation = self.visit(arguments.kwarg.annotation)
        arguments.defaults = [self.visit(value) for value in arguments.defaults]
        arguments.kw_defaults = [
            self.visit(value) if value is not None else None
            for value in arguments.kw_defaults
        ]

    def _rename_arguments(self, arguments: ast.arguments, scope: _Scope) -> None:
        for argument in arguments.posonlyargs + arguments.args:
            argument.arg = scope.mapping.get(argument.arg, argument.arg)
        if arguments.vararg is not None:
            arguments.vararg.arg = scope.mapping.get(
                arguments.vararg.arg, arguments.vararg.arg
            )
        if arguments.kwarg is not None:
            arguments.kwarg.arg = scope.mapping.get(
                arguments.kwarg.arg, arguments.kwarg.arg
            )

    def _visit_function(self, node: ast.AST) -> ast.AST:
        node.name = self._resolve(node.name)
        node.decorator_list = [self.visit(value) for value in node.decorator_list]
        self._visit_arguments_in_parent(node.args)
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        node.body = _without_docstring(node.body)
        scope = self._function_scope(node)
        self.scopes.append(scope)
        self._rename_arguments(node.args, scope)
        node.body = [self.visit(statement) for statement in node.body]
        self.scopes.pop()
        return node

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        self._visit_arguments_in_parent(node.args)
        scope = self._function_scope(node, kind="lambda")
        self.scopes.append(scope)
        self._rename_arguments(node.args, scope)
        node.body = self.visit(node.body)
        self.scopes.pop()
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.name = self._resolve(node.name)
        node.decorator_list = [self.visit(value) for value in node.decorator_list]
        node.bases = [self.visit(value) for value in node.bases]
        node.keywords = [self.visit(value) for value in node.keywords]
        node.body = _without_docstring(node.body)
        self.scopes.append(self._class_scope(node))
        node.body = [self.visit(statement) for statement in node.body]
        self.scopes.pop()
        return node

    def visit_Import(self, node: ast.Import) -> ast.Import:
        for alias in node.names:
            binding = alias.asname or alias.name.split(".", 1)[0]
            renamed = self._resolve(binding)
            if renamed != binding:
                alias.asname = renamed
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.ImportFrom:
        for alias in node.names:
            if alias.name == "*":
                continue
            binding = alias.asname or alias.name
            renamed = self._resolve(binding)
            if renamed != binding:
                alias.asname = renamed
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        if node.type is not None:
            node.type = self.visit(node.type)
        if node.name:
            node.name = self._resolve(node.name)
        node.body = [self.visit(statement) for statement in node.body]
        return node

    def _visit_comprehension(self, node: ast.AST) -> ast.AST:
        generators = node.generators
        if not generators:
            return node
        generators[0].iter = self.visit(generators[0].iter)
        self.scopes.append(self._comprehension_scope(generators))
        generators[0].target = self.visit(generators[0].target)
        generators[0].ifs = [self.visit(value) for value in generators[0].ifs]
        for generator in generators[1:]:
            generator.iter = self.visit(generator.iter)
            generator.target = self.visit(generator.target)
            generator.ifs = [self.visit(value) for value in generator.ifs]
        if isinstance(node, ast.DictComp):
            node.key = self.visit(node.key)
            node.value = self.visit(node.value)
        else:
            node.elt = self.visit(node.elt)
        self.scopes.pop()
        return node

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension


def obfuscate_source(source: str, filename: str = "<module>") -> str:
    """Strip comments/docstrings and rename implementation identifiers."""
    try:
        tree = ast.parse(source, filename=filename)
        compile(tree, filename, "exec")
    except SyntaxError as exc:
        raise ProtectionError("Cannot obfuscate invalid source: {}".format(exc)) from exc
    try:
        transformed = _ScopeAwareRenamer(source, tree).visit(tree)
        ast.fix_missing_locations(transformed)
        result = ast.unparse(transformed) + "\n"
        compile(result, filename, "exec")
    except (TypeError, ValueError, SyntaxError) as exc:
        raise ProtectionError("Source obfuscation failed: {}".format(exc)) from exc
    return result
