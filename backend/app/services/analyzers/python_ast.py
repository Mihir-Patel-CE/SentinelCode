import ast
import re
import builtins
from typing import List, Set, Optional
from app.services.analyzers.base import BaseAnalyzer, AnalysisResult
from app.schemas.review import FindingCreate

PYTHON_BUILTINS = set(dir(builtins)) | {
    "__name__", "__doc__", "__file__", "__package__", "__loader__", "__spec__",
    "self", "cls", "args", "kwargs"
}

SECRET_PATTERN = re.compile(
    r'(?i)(api[_-]?key|secret[_-]?key|password|aws_secret_access_key|private[_-]?key)\s*=\s*["\']([a-zA-Z0-9_\-\.\/+=]{12,})["\']'
)


def get_line_snippet(lines: List[str], line_no: Optional[int]) -> Optional[str]:
    if line_no is not None and 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return None


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, lines: List[str], tree: Optional[ast.AST] = None):
        self.findings: List[FindingCreate] = []
        self.lines = lines
        self.module_scope: Set[str] = set(PYTHON_BUILTINS)
        self.scope_stack: List[Set[str]] = []
        self.known_dict_keys: dict[str, Set[str]] = {}
        self.function_defs: dict[str, dict] = {}
        self.current_function: Optional[ast.FunctionDef] = None

        if tree is not None:
            self._init_module_symbols(tree)
            self._init_dict_schemas(tree)
            self._init_function_signatures(tree)

    def _init_module_symbols(self, tree: ast.AST):
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.module_scope.add(node.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.module_scope.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.module_scope.add(alias.asname or alias.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    self._collect_target_names(target, self.module_scope)
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                if hasattr(node, "target"):
                    self._collect_target_names(node.target, self.module_scope)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self._collect_target_names(node.target, self.module_scope)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars:
                        self._collect_target_names(item.optional_vars, self.module_scope)
            elif isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.name:
                        self.module_scope.add(handler.name)

    def _collect_target_names(self, target: ast.AST, out: Set[str]):
        if isinstance(target, ast.Name):
            out.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._collect_target_names(elt, out)

    def _init_dict_schemas(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Dict):
                        keys = {
                            k.value for k in node.value.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)
                        }
                        if keys:
                            self.known_dict_keys.setdefault(target.id, set()).update(keys)
                    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                            self.known_dict_keys.setdefault(target.value.id, set()).add(target.slice.value)

    def _init_function_signatures(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self.function_defs[node.name] = {
                    "params": [a.arg for a in node.args.args],
                    "body": node.body
                }

    def _is_case_normalized(self, expr: ast.AST) -> bool:
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in ("lower", "upper", "casefold")
        )

    def _find_len_call_collection(self, expr: ast.AST) -> Optional[str]:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "len":
                if sub.args and isinstance(sub.args[0], ast.Name):
                    return sub.args[0].id
        return None

    def _has_empty_guard(self, func_node: Optional[ast.FunctionDef], coll_name: str) -> bool:
        if not func_node:
            return False
        for sub in ast.walk(func_node):
            if isinstance(sub, ast.If):
                test = sub.test
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    if isinstance(test.operand, ast.Name) and test.operand.id == coll_name:
                        return True
                if isinstance(test, ast.Name) and test.id == coll_name:
                    return True
                if isinstance(test, ast.Compare):
                    for part in [test.left] + test.comparators:
                        if isinstance(part, ast.Call) and isinstance(part.func, ast.Name) and part.func.id == "len":
                            if part.args and isinstance(part.args[0], ast.Name) and part.args[0].id == coll_name:
                                return True
        return False

    def _function_validates_param(self, body: List[ast.stmt], pname: str) -> bool:
        for stmt in body:
            if isinstance(stmt, ast.If):
                for sub in ast.walk(stmt.test):
                    if isinstance(sub, ast.Compare):
                        names = [n.id for n in ast.walk(sub) if isinstance(n, ast.Name)]
                        if pname in names:
                            return True
        return False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.module_scope.add(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            name = alias.asname or alias.name
            self.module_scope.add(name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_fn = self.current_function
        self.current_function = node
        self.module_scope.add(node.name)
        line_no = getattr(node, "lineno", 1)

        # Check for mutable default arguments
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                type_name = "list" if isinstance(default, ast.List) else ("dict" if isinstance(default, ast.Dict) else "set")
                self.findings.append(FindingCreate(
                    rule_id="BUG-PY-001",
                    title=f"Mutable default argument `{type_name}` in function `{node.name}`",
                    description=(
                        f"Default arguments in Python are evaluated once at function definition time. "
                        f"Mutating `{type_name}` persists modifications across separate calls."
                    ),
                    severity="medium",
                    category="bug",
                    source="static",
                    line_start=line_no,
                    line_end=line_no,
                    column_start=getattr(default, "col_offset", None),
                    column_end=getattr(default, "end_col_offset", None),
                    evidence=get_line_snippet(self.lines, line_no),
                    confidence="high",
                    suggested_fix="Default to `None` and instantiate the collection inside the function body.",
                    fix_diff=f"- def {node.name}(..., param={type_name}()):\n+ def {node.name}(..., param=None):\n+     if param is None: param = {type_name}()"
                ))

        # Check for unreachable code after return/raise in function body
        self._check_unreachable_code(node.body)

        # Build local scope for this function
        local_scope: Set[str] = set()
        for arg in node.args.args:
            local_scope.add(arg.arg)
        for arg in getattr(node.args, "posonlyargs", []):
            local_scope.add(arg.arg)
        for arg in getattr(node.args, "kwonlyargs", []):
            local_scope.add(arg.arg)
        if node.args.vararg:
            local_scope.add(node.args.vararg.arg)
        if node.args.kwarg:
            local_scope.add(node.args.kwarg.arg)

        # Pre-scan local assignments
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    self._collect_target_names(t, local_scope)
            elif isinstance(sub, (ast.AugAssign, ast.AnnAssign)):
                if hasattr(sub, "target"):
                    self._collect_target_names(sub.target, local_scope)
            elif isinstance(sub, (ast.For, ast.AsyncFor)):
                self._collect_target_names(sub.target, local_scope)
            elif isinstance(sub, (ast.With, ast.AsyncWith)):
                for item in sub.items:
                    if item.optional_vars:
                        self._collect_target_names(item.optional_vars, local_scope)
            elif isinstance(sub, ast.ExceptHandler):
                if sub.name:
                    local_scope.add(sub.name)

        self.scope_stack.append(local_scope)
        self.generic_visit(node)
        self.scope_stack.pop()
        self.current_function = prev_fn

    def _handle_comprehension(self, node: ast.AST, is_dict: bool = False):
        comp_scope: Set[str] = set()
        for gen in node.generators:
            self._collect_target_names(gen.target, comp_scope)
        self.scope_stack.append(comp_scope)
        for gen in node.generators:
            self.visit(gen.iter)
            for if_clause in gen.ifs:
                self.visit(if_clause)
        if is_dict:
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.scope_stack.pop()

    def visit_ListComp(self, node: ast.ListComp):
        self._handle_comprehension(node, is_dict=False)

    def visit_SetComp(self, node: ast.SetComp):
        self._handle_comprehension(node, is_dict=False)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self._handle_comprehension(node, is_dict=False)

    def visit_DictComp(self, node: ast.DictComp):
        self._handle_comprehension(node, is_dict=True)

    def visit_Lambda(self, node: ast.Lambda):
        lambda_scope: Set[str] = set()
        for arg in node.args.args:
            lambda_scope.add(arg.arg)
        for arg in getattr(node.args, "posonlyargs", []):
            lambda_scope.add(arg.arg)
        for arg in getattr(node.args, "kwonlyargs", []):
            lambda_scope.add(arg.arg)
        if node.args.vararg:
            lambda_scope.add(node.args.vararg.arg)
        if node.args.kwarg:
            lambda_scope.add(node.args.kwarg.arg)
        self.scope_stack.append(lambda_scope)
        self.visit(node.body)
        self.scope_stack.pop()

    def visit_With(self, node: ast.With):
        for item in node.items:
            if item.optional_vars:
                if self.scope_stack:
                    self._collect_target_names(item.optional_vars, self.scope_stack[-1])
                else:
                    self._collect_target_names(item.optional_vars, self.module_scope)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith):
        for item in node.items:
            if item.optional_vars:
                if self.scope_stack:
                    self._collect_target_names(item.optional_vars, self.scope_stack[-1])
                else:
                    self._collect_target_names(item.optional_vars, self.module_scope)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.module_scope.add(node.name)
        self._check_unreachable_code(node.body)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.module_scope.add(node.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if not self.scope_stack:
                self._collect_target_names(target, self.module_scope)
            else:
                self._collect_target_names(target, self.scope_stack[-1])
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        if not self.scope_stack:
            self._collect_target_names(node.target, self.module_scope)
        else:
            self._collect_target_names(node.target, self.scope_stack[-1])
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            in_locals = any(node.id in scope for scope in self.scope_stack)
            if (
                not in_locals
                and node.id not in self.module_scope
                and not node.id.startswith("_")
            ):
                line_no = getattr(node, "lineno", 1)
                self.findings.append(FindingCreate(
                    rule_id="BUG-PY-004",
                    title=f"Undefined name or unresolved reference `{node.id}`",
                    description=(
                        f"Variable or function `{node.id}` is referenced before assignment or definition. "
                        "Executing this line will raise a `NameError` at runtime."
                    ),
                    severity="high",
                    category="bug",
                    source="static",
                    line_start=line_no,
                    line_end=line_no,
                    column_start=getattr(node, "col_offset", None),
                    column_end=getattr(node, "end_col_offset", None),
                    evidence=get_line_snippet(self.lines, line_no),
                    confidence="high",
                    suggested_fix=f"Define or import `{node.id}` prior to usage."
                ))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        # Missing dictionary key detection (KeyError)
        if isinstance(node.ctx, ast.Load):
            if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant):
                var_name = node.value.id
                key = node.slice.value
                if isinstance(key, str) and var_name in self.known_dict_keys:
                    known = self.known_dict_keys[var_name]
                    if len(known) >= 2 and key not in known:
                        line_no = getattr(node, "lineno", 1)
                        self.findings.append(FindingCreate(
                            rule_id="BUG-PY-006",
                            title=f"Missing dictionary key `{key}` causes KeyError",
                            description=(
                                f"Accessing `{var_name}['{key}']` using direct subscript lookup will raise a `KeyError` "
                                f"at runtime because `{key}` is not defined in the `{var_name}` dictionary schema."
                            ),
                            severity="high",
                            category="bug",
                            source="static",
                            line_start=line_no,
                            line_end=line_no,
                            column_start=getattr(node, "col_offset", None),
                            column_end=getattr(node, "end_col_offset", None),
                            evidence=get_line_snippet(self.lines, line_no),
                            confidence="high",
                            suggested_fix=f"Initialize `{key}` in `{var_name}` or access safely with `{var_name}.get('{key}').",
                            fix_diff=f"- {var_name}[\"{key}\"]\n+ {var_name}.get(\"{key}\", None)"
                        ))
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        line_no = getattr(node, "lineno", 1)
        # Check literal division or modulo by zero
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            if isinstance(node.right, ast.Constant) and node.right.value == 0:
                self.findings.append(FindingCreate(
                    rule_id="BUG-PY-005",
                    title="Division or modulo by zero",
                    description="Dividing or computing remainder with a literal zero will trigger a `ZeroDivisionError` exception.",
                    severity="high",
                    category="bug",
                    source="static",
                    line_start=line_no,
                    line_end=line_no,
                    evidence=get_line_snippet(self.lines, line_no),
                    confidence="high",
                    suggested_fix="Validate divisor is non-zero before performing arithmetic division."
                ))
            else:
                # Check unsafe division by collection length (ZeroDivisionError on empty list)
                coll_name = self._find_len_call_collection(node.right)
                if coll_name and not self._has_empty_guard(self.current_function, coll_name):
                    self.findings.append(FindingCreate(
                        rule_id="BUG-PY-007",
                        title=f"Unsafe division by collection length `len({coll_name})` without non-empty check",
                        description=(
                            f"Dividing by an expression containing `len({coll_name})` without verifying that the collection is "
                            f"non-empty will raise a `ZeroDivisionError` when `{coll_name}` is empty."
                        ),
                        severity="high",
                        category="bug",
                        source="static",
                        line_start=line_no,
                        line_end=line_no,
                        column_start=getattr(node, "col_offset", None),
                        column_end=getattr(node, "end_col_offset", None),
                        evidence=get_line_snippet(self.lines, line_no),
                        confidence="high",
                        suggested_fix=f"Guard against empty inputs before dividing: `if not {coll_name}: return 0.0`.",
                        fix_diff=f"- percentage = ... / (len({coll_name}) * 100)\n+ if not {coll_name}: return 0.0\n+ percentage = ... / (len({coll_name}) * 100)"
                    ))
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        line_no = getattr(node, "lineno", 1)
        # Inconsistent case-sensitive search check
        for op in node.ops:
            if isinstance(op, (ast.In, ast.NotIn, ast.Eq, ast.NotEq)):
                left_norm = self._is_case_normalized(node.left)
                for comp in node.comparators:
                    right_norm = self._is_case_normalized(comp)
                    if left_norm != right_norm:
                        if not isinstance(node.left, ast.Constant) and not isinstance(comp, ast.Constant):
                            self.findings.append(FindingCreate(
                                rule_id="BUG-PY-008",
                                title="Inconsistent case normalization in substring search or comparison",
                                description=(
                                    "One operand is normalized with `.lower()`, but the compared operand is not normalized. "
                                    "Searching or comparing strings with different casing will silently fail to match."
                                ),
                                severity="medium",
                                category="bug",
                                source="static",
                                line_start=line_no,
                                line_end=line_no,
                                column_start=getattr(node, "col_offset", None),
                                column_end=getattr(node, "end_col_offset", None),
                                evidence=get_line_snippet(self.lines, line_no),
                                confidence="high",
                                suggested_fix="Normalize both operands to the same case using `.lower()` or `.casefold()`.",
                                fix_diff="- if query.lower() in target:\n+ if query.lower() in target.lower():"
                            ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{func_name}"

        line_no = getattr(node, "lineno", 1)

        # Check domain parameter negative input validation
        if isinstance(node.func, ast.Name) and node.func.id in self.function_defs:
            fn_info = self.function_defs[node.func.id]
            params = fn_info["params"]
            for idx, arg in enumerate(node.args):
                if idx < len(params):
                    pname = params[idx]
                    if pname in ("age", "count", "quantity", "size", "price"):
                        if isinstance(arg, ast.UnaryOp) and isinstance(arg.op, ast.USub) and isinstance(arg.operand, ast.Constant):
                            val = -arg.operand.value
                            if not self._function_validates_param(fn_info["body"], pname):
                                self.findings.append(FindingCreate(
                                    rule_id="VAL-PY-001",
                                    title=f"Missing input validation for negative `{pname}` value",
                                    description=(
                                        f"Negative literal `{val}` is passed for domain parameter `{pname}` in call to `{node.func.id}`, "
                                        f"but `{node.func.id}` lacks boundary validation ensuring `{pname}` is non-negative."
                                    ),
                                    severity="low",
                                    category="quality",
                                    source="static",
                                    line_start=line_no,
                                    line_end=line_no,
                                    column_start=getattr(node, "col_offset", None),
                                    column_end=getattr(node, "end_col_offset", None),
                                    evidence=get_line_snippet(self.lines, line_no),
                                    confidence="high",
                                    suggested_fix=f"Add validation in `{node.func.id}`: `if {pname} <= 0: raise ValueError('{pname} must be positive')`.",
                                    fix_diff=f"- def {node.func.id}(...):\n+ def {node.func.id}(...):\n+     if {pname} <= 0: raise ValueError('{pname} must be positive')"
                                ))

        # 1. Dangerous Dynamic Evaluation
        if func_name in ("eval", "exec", "__import__"):
            self.findings.append(FindingCreate(
                rule_id="SEC-PY-004",
                title=f"Dangerous dynamic code execution using `{func_name}`",
                description="Executing arbitrary code via dynamic evaluation allows remote code execution (CWE-95).",
                severity="critical",
                category="security",
                source="static",
                line_start=line_no,
                line_end=line_no,
                evidence=get_line_snippet(self.lines, line_no),
                confidence="high",
                suggested_fix="Avoid dynamic evaluation. Use strict whitelists or safe parsers like `ast.literal_eval`.",
                fix_diff=f"- {func_name}(user_input)\n+ ast.literal_eval(user_input)"
            ))

        # 2. Command Injection
        if func_name in ("os.system", "os.popen"):
            self.findings.append(FindingCreate(
                rule_id="SEC-PY-002",
                title="Potential Command Injection via `os.system`",
                description="Executing shell commands without argument sanitization permits Command Injection (CWE-78).",
                severity="critical",
                category="security",
                source="static",
                line_start=line_no,
                line_end=line_no,
                evidence=get_line_snippet(self.lines, line_no),
                confidence="high",
                suggested_fix="Use `subprocess.run` with argument lists and `shell=False`.",
                fix_diff="- os.system(cmd)\n+ subprocess.run(shlex.split(cmd), check=True)"
            ))

        if func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(FindingCreate(
                        rule_id="SEC-PY-002",
                        title="Subprocess execution with `shell=True`",
                        description="Passing `shell=True` to subprocess invokes an intermediate shell interpreter prone to injection.",
                        severity="high",
                        category="security",
                        source="static",
                        line_start=line_no,
                        line_end=line_no,
                        evidence=get_line_snippet(self.lines, line_no),
                        confidence="high",
                        suggested_fix="Set `shell=False` and supply command arguments as a list.",
                        fix_diff="- subprocess.run(cmd, shell=True)\n+ subprocess.run(shlex.split(cmd), shell=False)"
                    ))

        # 3. Insecure Deserialization
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads"):
            self.findings.append(FindingCreate(
                rule_id="SEC-PY-003",
                title="Insecure Deserialization via `pickle`",
                description="Deserializing untrusted pickle payloads enables arbitrary Remote Code Execution (CWE-502).",
                severity="critical",
                category="security",
                source="static",
                line_start=line_no,
                line_end=line_no,
                evidence=get_line_snippet(self.lines, line_no),
                confidence="high",
                suggested_fix="Use structured data exchange like JSON or Protocol Buffers.",
                fix_diff="- data = pickle.loads(payload)\n+ data = json.loads(payload)"
            ))

        if func_name == "yaml.load":
            has_safe = any(
                kw.arg == "Loader" and getattr(kw.value, "id", "") in ("SafeLoader", "CSafeLoader")
                for kw in node.keywords
            )
            if not has_safe:
                self.findings.append(FindingCreate(
                    rule_id="SEC-PY-003",
                    title="Unsafe YAML deserialization without `SafeLoader`",
                    description="Calling `yaml.load()` without SafeLoader can construct arbitrary objects.",
                    severity="high",
                    category="security",
                    source="static",
                    line_start=line_no,
                    line_end=line_no,
                    evidence=get_line_snippet(self.lines, line_no),
                    confidence="high",
                    suggested_fix="Use `yaml.safe_load(payload)`.",
                    fix_diff="- yaml.load(payload)\n+ yaml.safe_load(payload)"
                ))

        # 4. Weak Cryptographic Hash
        if func_name in ("hashlib.md5", "hashlib.sha1"):
            self.findings.append(FindingCreate(
                rule_id="SEC-PY-005",
                title=f"Insecure cryptographic hash `{func_name}`",
                description=f"`{func_name}` is broken against collision attacks (CWE-328).",
                severity="medium",
                category="security",
                source="static",
                line_start=line_no,
                line_end=line_no,
                evidence=get_line_snippet(self.lines, line_no),
                confidence="high",
                suggested_fix="Use SHA-256 for integrity or Argon2/bcrypt for passwords.",
                fix_diff=f"- {func_name}(...)\n+ hashlib.sha256(...)"
            ))

        # 5. SQL Injection via execute(...)
        if func_name.endswith(".execute"):
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.JoinedStr):
                    self.findings.append(FindingCreate(
                        rule_id="SEC-PY-001",
                        title="SQL Injection vulnerability via f-string query formatting",
                        description="Interpolating variables directly into SQL queries causes SQL Injection (CWE-89).",
                        severity="critical",
                        category="security",
                        source="static",
                        line_start=line_no,
                        line_end=line_no,
                        evidence=get_line_snippet(self.lines, line_no),
                        confidence="high",
                        suggested_fix="Use parameterized queries with placeholder bindings.",
                        fix_diff='- cursor.execute(f"SELECT * FROM tbl WHERE id = {uid}")\n+ cursor.execute("SELECT * FROM tbl WHERE id = %s", (uid,))'
                    ))
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                    self.findings.append(FindingCreate(
                        rule_id="SEC-PY-001",
                        title="SQL Injection vulnerability via string concatenation or % formatting",
                        description="Concatenating input strings into SQL statements bypasses query escaping.",
                        severity="critical",
                        category="security",
                        source="static",
                        line_start=line_no,
                        line_end=line_no,
                        evidence=get_line_snippet(self.lines, line_no),
                        confidence="high",
                        suggested_fix="Bind parameters separately to `execute()`.",
                        fix_diff='- cursor.execute("SELECT * FROM tbl WHERE name = \'" + name + "\'")\n+ cursor.execute("SELECT * FROM tbl WHERE name = %s", (name,))'
                    ))

        # 6. Insecure tempfile.mktemp
        if func_name in ("tempfile.mktemp",):
            self.findings.append(FindingCreate(
                rule_id="SEC-PY-007",
                title="Insecure temporary file creation with `tempfile.mktemp`",
                description="`mktemp` introduces a time-of-check to time-of-use (TOCTOU) race condition (CWE-377).",
                severity="medium",
                category="security",
                source="static",
                line_start=line_no,
                line_end=line_no,
                evidence=get_line_snippet(self.lines, line_no),
                confidence="high",
                suggested_fix="Use `tempfile.NamedTemporaryFile` instead.",
                fix_diff="- path = tempfile.mktemp()\n+ with tempfile.NamedTemporaryFile(delete=False) as f: path = f.name"
            ))

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.name:
            if self.scope_stack:
                self.scope_stack[-1].add(node.name)
            else:
                self.module_scope.add(node.name)
        line_no = getattr(node, "lineno", 1)
        if node.type is None:
            self.findings.append(FindingCreate(
                rule_id="BUG-PY-002",
                title="Bare `except:` clause catches all exceptions",
                description="Bare `except:` suppresses `KeyboardInterrupt` and `SystemExit`, complicating debugging.",
                severity="low",
                category="quality",
                source="static",
                line_start=line_no,
                line_end=line_no,
                evidence=get_line_snippet(self.lines, line_no),
                confidence="high",
                suggested_fix="Catch explicit exceptions like `except Exception as e:`."
            ))
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        line_no = getattr(node, "lineno", 1)
        self.findings.append(FindingCreate(
            rule_id="QUAL-PY-001",
            title="Use of `assert` in application logic",
            description="Assert statements are eliminated in optimized bytecode (`-O` flag); do not rely on them for validation.",
            severity="low",
            category="quality",
            source="static",
            line_start=line_no,
            line_end=line_no,
            evidence=get_line_snippet(self.lines, line_no),
            confidence="high",
            suggested_fix="Raise explicit validation exceptions."
        ))
        self.generic_visit(node)

    def _check_unreachable_code(self, statements: List[ast.stmt]):
        for idx, stmt in enumerate(statements[:-1]):
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                next_stmt = statements[idx + 1]
                line_no = getattr(next_stmt, "lineno", 1)
                self.findings.append(FindingCreate(
                    rule_id="BUG-PY-003",
                    title="Unreachable dead code",
                    description=f"Statement after `{type(stmt).__name__.lower()}` can never be executed.",
                    severity="low",
                    category="bug",
                    source="static",
                    line_start=line_no,
                    line_end=line_no,
                    evidence=get_line_snippet(self.lines, line_no),
                    confidence="high",
                    suggested_fix="Remove unreachable dead code or fix control flow."
                ))
                break


class PythonAnalyzer(BaseAnalyzer):
    @property
    def language(self) -> str:
        return "python"

    @property
    def name(self) -> str:
        return "Python Native AST & Security Analyzer"

    @property
    def features(self) -> List[str]:
        return [
            "Syntax & Parsing Verification (ast.parse)",
            "Scope & Undefined Name Resolution (NameError detection)",
            "Dead / Unreachable Code Detection",
            "ZeroDivisionError static analysis",
            "OWASP Top 10 Security Rules (SQLi, Command Injection, Insecure Deserialization, RCE)",
            "Hardcoded Credential & API Token Scanning",
            "Mutable Default Argument & Bare Except Auditing",
            "Dictionary Schema & Missing Key Detection (KeyError)",
            "Empty Collection Division Analysis (ZeroDivisionError)",
            "Inconsistent Case Search & Comparison Auditing",
            "Domain Value Boundary Validation (Negative Domain Inputs)"
        ]

    @property
    def limitations(self) -> str:
        return "Analyzes single Python files statically. Dynamic imports (`importlib`) and runtime reflection cannot be fully verified without sandboxed execution."

    def analyze(self, code: str) -> AnalysisResult:
        findings: List[FindingCreate] = []
        lines = code.splitlines()
        status = "completed"

        # Step 1: Safe AST parsing
        try:
            tree = ast.parse(code)
            visitor = PythonASTVisitor(lines, tree=tree)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError as e:
            status = "completed_with_limitations"
            line_snippet = get_line_snippet(lines, e.lineno) or e.text.strip() if e.text else ""
            findings.append(FindingCreate(
                rule_id="SYN-PY-001",
                title=f"Python Syntax Error: {e.msg}",
                description=f"Syntax parsing error at line {e.lineno}, col {e.offset}: {e.msg}",
                severity="high",
                category="syntax",
                source="static",
                line_start=e.lineno or 1,
                line_end=e.lineno or 1,
                column_start=e.offset,
                evidence=line_snippet,
                confidence="high",
                suggested_fix="Correct the syntax discrepancy to restore valid Python grammar."
            ))
        except Exception as ex:
            status = "failed"
            return AnalysisResult(
                status="failed",
                language="python",
                findings=[],
                error_message=f"Parser encountered unhandled error: {str(ex)}"
            )

        # Step 2: Secret & Credential Scanning
        for idx, line in enumerate(lines, start=1):
            match = SECRET_PATTERN.search(line)
            if match:
                key_name = match.group(1)
                findings.append(FindingCreate(
                    rule_id="SEC-PY-006",
                    title=f"Hardcoded credential detected: `{key_name}`",
                    description=f"Hardcoded sensitive secret `{key_name}` violates credential isolation (CWE-798).",
                    severity="critical",
                    category="security",
                    source="static",
                    line_start=idx,
                    line_end=idx,
                    evidence=line.strip(),
                    confidence="high",
                    suggested_fix="Extract secret to an environment variable or secret vault.",
                    fix_diff=f"- {key_name} = \"{match.group(2)[:4]}...\"\n+ {key_name} = os.getenv('{key_name.upper()}')"
                ))

        coverage = f"Checked {len(lines)} lines of Python code across 7 static analysis layers."
        return AnalysisResult(
            status=status,
            language="python",
            findings=findings,
            coverage_summary=coverage,
            limitations=self.limitations
        )
