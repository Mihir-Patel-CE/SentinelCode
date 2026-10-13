import re
from typing import Dict, List, Optional
from app.services.analyzers.base import BaseAnalyzer
from app.services.analyzers.python_ast import PythonAnalyzer
from app.services.analyzers.javascript import JavaScriptAnalyzer
from app.services.analyzers.java import JavaAnalyzer
from app.services.analyzers.c_analyzer import CAnalyzer
from app.services.analyzers.cpp_analyzer import CppAnalyzer
from app.schemas.review import LanguageCapability


class AnalyzerRegistry:
    """
    Central registry for language analyzers with automatic language detection,
    extensible adapter hooks, and capability introspection.
    """

    def __init__(self):
        self._analyzers: Dict[str, BaseAnalyzer] = {}
        # Register core default analyzers
        self.register(PythonAnalyzer())
        self.register(JavaScriptAnalyzer(is_typescript=False))
        self.register(JavaScriptAnalyzer(is_typescript=True))
        self.register(JavaAnalyzer())
        self.register(CAnalyzer())
        self.register(CppAnalyzer())

    def register(self, analyzer: BaseAnalyzer) -> None:
        """Registers or replaces an analyzer for a specific language identifier."""
        self._analyzers[analyzer.language.lower()] = analyzer

    def canonical_language(self, language: str) -> str:
        """Resolves language identifier to its canonical form."""
        lang_key = language.lower().strip()
        alias_map = {
            "py": "python",
            "js": "javascript",
            "node": "javascript",
            "ts": "typescript",
            "tsx": "typescript",
            "jsx": "javascript",
            "c++": "cpp",
            "cxx": "cpp",
            "cc": "cpp",
            "hpp": "cpp",
            "h": "c",
            "c": "c",
            "cpp": "cpp",
        }
        return alias_map.get(lang_key, lang_key)

    def get(self, language: str) -> Optional[BaseAnalyzer]:
        """Retrieves analyzer by language name or alias."""
        canonical = self.canonical_language(language)
        return self._analyzers.get(canonical)

    def detect_language(self, code: str) -> str:
        """
        Heuristically detects programming language from syntax markers,
        keywords, and structural declarations.
        Guarantees that C and C++ are never misidentified as Python.
        """
        trimmed = code.strip()

        # Score counters
        scores = {
            "python": 0,
            "typescript": 0,
            "javascript": 0,
            "java": 0,
            "c": 0,
            "cpp": 0,
            "go": 0,
            "rust": 0
        }

        # C++ specific indicators
        cpp_includes = re.search(
            r'#include\s*<(iostream|vector|string|memory|map|set|utility|algorithm|thread|mutex|sstream|fstream|chrono|functional|type_traits|array|queue|stack|deque|list|unordered_map|unordered_set|bitset|numeric|climits|cmath|cstring|cstdio|cstdlib|bits/stdc\+\+\.h)>',
            trimmed
        )
        if cpp_includes:
            scores["cpp"] += 15

        if re.search(r'\bstd::|\busing\s+namespace\s+[a-zA-Z0-9_:]+\b|\busing\s+std::', trimmed):
            scores["cpp"] += 12
        if re.search(r'\b(cout|cin|cerr)\s*<<|\bcin\s*>>|\bendl\b', trimmed):
            scores["cpp"] += 10
        if re.search(r'\b(nullptr|constexpr|override|final|noexcept)\b', trimmed):
            scores["cpp"] += 10
        if re.search(r'\b(template\s*<|typename\s+[a-zA-Z0-9_])', trimmed):
            scores["cpp"] += 10
        if re.search(r'\bnamespace\s+[a-zA-Z0-9_]+\s*\{', trimmed):
            scores["cpp"] += 10
        if re.search(r'\b(public|private|protected)\s*:', trimmed):
            scores["cpp"] += 10
        if re.search(r'\b(new\s+[a-zA-Z0-9_]+(\[|\()|delete\s+|delete\[\])', trimmed):
            scores["cpp"] += 8
        if re.search(r'\bclass\s+[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*(public|private|protected)\s+[a-zA-Z0-9_]+', trimmed):
            scores["cpp"] += 12
        if re.search(r'\bcatch\s*\(\s*(const\s+)?std::', trimmed):
            scores["cpp"] += 8
        if re.search(r'#include\s*["<][a-zA-Z0-9_./]+\.(hpp|hxx|hh)[">]', trimmed):
            scores["cpp"] += 10

        # C indicators
        c_includes = re.search(
            r'#include\s*<(stdio\.h|stdlib\.h|string\.h|unistd\.h|stdbool\.h|stdint\.h|errno\.h|fcntl\.h|pthread\.h|time\.h|math\.h)>',
            trimmed
        )
        if c_includes:
            scores["c"] += 10
            # C++ can also include C headers, but with lower weight
            scores["cpp"] += 3

        if re.search(r'\b(printf|scanf|fprintf|sprintf|snprintf)\s*\(', trimmed):
            scores["c"] += 7
            scores["cpp"] += 3
        if re.search(r'\b(malloc|calloc|realloc|free)\s*\(', trimmed):
            scores["c"] += 8
            scores["cpp"] += 3
        if re.search(r'\b(strcpy|strcat|strncpy|strncat|strlen|strcmp)\s*\(', trimmed):
            scores["c"] += 7
            scores["cpp"] += 3
        if re.search(r'\btypedef\s+struct\b', trimmed):
            scores["c"] += 8
        if re.search(r'\bNULL\b', trimmed):
            scores["c"] += 5
            scores["cpp"] += 2
        if re.search(r'int\s+main\s*\(\s*(void|int\s+argc)?', trimmed):
            scores["c"] += 5
            scores["cpp"] += 5
        if re.search(r'#include\s*["<][a-zA-Z0-9_./]+\.h[">]', trimmed):
            scores["c"] += 5
            scores["cpp"] += 2

        # Java indicators
        if re.search(r'\b(public\s+class|public\s+static\s+void\s+main|System\.out\.print|package\s+[a-z]+;)\b', trimmed):
            scores["java"] += 12
        if re.search(r'\bimport\s+java[x]?\.[a-zA-Z0-9_.*]+;', trimmed):
            scores["java"] += 12
        if re.search(r'\b(public|protected|private)\s+(class|interface|enum|record)\s+[A-Z][a-zA-Z0-9_]*', trimmed):
            scores["java"] += 10
        if re.search(r'\b(private|protected|public)\s+(static\s+)?(final\s+)?[A-Z][a-zA-Z0-9_<>]*\s+[a-z][a-zA-Z0-9_]*', trimmed):
            scores["java"] += 6
        if re.search(r'\b(extends|implements|throws)\s+[A-Z][a-zA-Z0-9_]*', trimmed):
            scores["java"] += 8
        if re.search(r'\bString(\[\])?\s+[a-zA-Z_]', trimmed):
            scores["java"] += 6
        if re.search(r'\bboolean\b', trimmed):
            scores["java"] += 5
        if re.search(r'@Override\b', trimmed):
            scores["java"] += 6
        if re.search(r'\bSystem\.(out|err|in)\b', trimmed):
            scores["java"] += 8

        # Python indicators
        if re.search(r'^\s*def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(.*?\)\s*:', trimmed, re.MULTILINE):
            scores["python"] += 8
        if re.search(r'^\s*import\s+[a-zA-Z_]|^\s*from\s+[a-zA-Z_]+.*import', trimmed, re.MULTILINE):
            scores["python"] += 5
        if re.search(r'\b(elif|self|__init__|None|True|False)\b', trimmed):
            scores["python"] += 4
        if re.search(r'"""|\'\'\'', trimmed):
            scores["python"] += 2

        # TypeScript specific
        if re.search(r'\b(interface\s+[A-Z]|type\s+[A-Z][a-zA-Z0-9_]*\s*=|<\s*[A-Z]\s*>)\b', trimmed):
            scores["typescript"] += 8
        if re.search(r':\s*(string|number|boolean|any|void|Record<|Array<)', trimmed):
            scores["typescript"] += 6

        # JavaScript / TypeScript general
        if re.search(r'\b(const|let|var)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=', trimmed):
            scores["javascript"] += 4
            scores["typescript"] += 4
        if re.search(r'\bfunction\s+[a-zA-Z_]|\bconsole\.log\b|\b=>', trimmed):
            scores["javascript"] += 4
            scores["typescript"] += 4

        # Go indicators
        if re.search(r'\bpackage\s+main\b|\bfunc\s+main\(\)', trimmed):
            scores["go"] += 8

        # Rust indicators
        if re.search(r'\bfn\s+main\(\)|\blet\s+mut\s+|\bprintln!|\bimpl\s+', trimmed):
            scores["rust"] += 8

        # General highest scoring language above threshold
        best_lang = max(scores, key=scores.get)
        max_score = scores[best_lang]

        if max_score > 0:
            # If the highest score is in C/C++ family, tie-break between C and C++
            if best_lang in ("c", "cpp"):
                has_cpp_indicators = (
                    scores["cpp"] > scores["c"]
                    or bool(cpp_includes)
                    or bool(re.search(r'\b(std::|cout|cin|cerr|nullptr|constexpr|override|noexcept|template\s*<|namespace\s+[a-zA-Z0-9_]+\s*\{|(public|private|protected)\s*:)\b', trimmed))
                )
                if has_cpp_indicators and scores["cpp"] > 0:
                    return "cpp"
                if scores["c"] > 0:
                    return "c"
                return "cpp"

            # If tied between JavaScript and TypeScript without TS-specific markers, default to JavaScript
            if best_lang in ("javascript", "typescript"):
                if scores["typescript"] > scores["javascript"]:
                    return "typescript"
                return "javascript"

            return best_lang

        # Fallback check:
        # If code has C++ signatures
        if any(marker in trimmed for marker in ("<iostream>", "std::", "using namespace", "cout", "cin", "nullptr", "delete ", "delete[]")):
            return "cpp"

        # If code has C signatures
        if any(marker in trimmed for marker in ("#include", "#define", "printf", "scanf", "malloc", "free", "int main", "void main", "char *")):
            return "c"

        # If code has Java signatures
        if any(marker in trimmed for marker in ("System.out", "public static void main", "public class ", "package ")):
            return "java"

        # If code has JavaScript / TypeScript signatures
        if any(marker in trimmed for marker in ("console.log", "document.", "window.", "export default", "export const")):
            return "javascript"

        # If code has Python signatures
        if any(marker in trimmed for marker in ("def ", "import ", "from ", "elif ", "self.")):
            return "python"

        # If code contains curly braces and semicolons and no Python keywords, never default to Python!
        has_curly_braces = "{" in trimmed and "}" in trimmed
        has_semicolons = ";" in trimmed
        has_python_keywords = bool(re.search(r'\b(def|import|from|elif|self)\b', trimmed))
        if has_curly_braces and has_semicolons and not has_python_keywords:
            if "class " in trimmed:
                return "cpp"
            return "c"

        # Fallback to python
        return "python"

    def get_supported_languages(self) -> List[LanguageCapability]:
        """Returns the public list of language capabilities and analyzer coverage."""
        result = []
        for lang_id, analyzer in self._analyzers.items():
            result.append(LanguageCapability(
                id=lang_id,
                name=analyzer.name,
                status="supported",
                features=analyzer.features,
                limitations=analyzer.limitations
            ))

        # Add planned languages for transparency
        result.append(LanguageCapability(
            id="go",
            name="Go Static Analyzer (Planned)",
            status="planned",
            features=["Syntax checks", "Concurrency race condition heuristics", "Goroutine leak inspection"],
            limitations="In development. Currently analyzed via advisory AI reasoning."
        ))
        result.append(LanguageCapability(
            id="rust",
            name="Rust Static Analyzer (Planned)",
            status="planned",
            features=["Ownership borrow-checker heuristics", "Unsafe block auditing"],
            limitations="In development. Currently analyzed via advisory AI reasoning."
        ))

        return result


registry = AnalyzerRegistry()
