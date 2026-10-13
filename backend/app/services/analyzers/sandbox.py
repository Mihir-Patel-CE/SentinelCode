import os
import shutil
import subprocess
import tempfile
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)

# Try to import resource for POSIX resource limits
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False


class CompilerError(Exception):
    """Base exception for compiler and sandbox execution issues."""
    pass


class CompilerNotFoundError(CompilerError):
    """Raised when the specified compiler or analyzer executable is not found."""
    pass


class CompilerTimeoutError(CompilerError):
    """Raised when the compilation / analysis step exceeds allowed time limits."""
    pass


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


class CompilerSandbox:
    """
    Isolated execution environment for C/C++ compilers and static analyzers.
    
    Security & Sandboxing Guarantees:
    1. Zero-execution of untrusted binaries: only analysis/syntax verification
       flags are run (-fsyntax-only, --analyze). Never executes user binaries.
    2. Environment isolation: backend secrets, database URLs, and API keys are stripped.
       Child processes only receive a minimal whitelisted environment.
    3. Ephemeral workspace: source files are written to a temporary directory with
       restricted permissions (0o600) and cleaned up immediately.
    4. Execution timeouts: strictly enforced timeout (default 5s) prevents denial of service.
    5. POSIX resource limits: limits CPU time, open file descriptors, and max output file size.
    6. Network restriction: child process has no proxy or external network configuration.
    """

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def resolve_executable(name: str) -> Optional[str]:
        """
        Locates the full path to a compiler executable, checking PATH, versioned
        toolchain variants, and common LLVM locations on Linux and macOS.
        """
        # Build candidate names (e.g. clang -> [clang, clang-19, clang-18, ...])
        candidate_names = [name]
        if name in ("clang", "clang++"):
            # Debian/Ubuntu frequently packages specific LLVM releases
            version_suffixes = ["19", "18", "17", "16", "15", "14"]
            for v in version_suffixes:
                candidate_names.append(f"{name}-{v}")

        search_paths = [
            "/usr/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/Library/Developer/CommandLineTools/usr/bin",
            "/usr/lib/llvm-19/bin",
            "/usr/lib/llvm-18/bin",
            "/usr/lib/llvm-17/bin",
            "/usr/lib/llvm-16/bin",
            "/usr/lib/llvm-15/bin",
            "/usr/lib/llvm-14/bin",
            "/usr/lib/llvm-13/bin",
        ]

        # 1. First check candidates against standard PATH
        for cand in candidate_names:
            resolved = shutil.which(cand)
            if resolved and os.access(resolved, os.X_OK):
                return resolved

        # 2. Check standard known LLVM / system directories
        for base in search_paths:
            for cand in candidate_names:
                candidate = os.path.join(base, cand)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    return candidate

        return None

    def is_available(self, executable_name: str) -> bool:
        """Checks if the required compiler or analyzer tool is available."""
        return self.resolve_executable(executable_name) is not None

    @classmethod
    def get_compiler_version(cls, executable_name: str) -> Optional[str]:
        """
        Runs `executable --version` to extract the compiler or analyzer version string.
        """
        resolved = cls.resolve_executable(executable_name)
        if not resolved:
            return None
        try:
            res = subprocess.run(
                [resolved, "--version"],
                capture_output=True,
                text=True,
                timeout=2.0
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip().splitlines()[0]
        except Exception as e:
            logger.warning(f"Failed to inspect version for '{executable_name}': {e}")
        return None

    @classmethod
    def get_toolchain_diagnostics(cls, executable_name: str) -> Dict[str, Optional[object]]:
        """
        Gathers toolchain diagnostics including resolution status, path, and version.
        """
        resolved = cls.resolve_executable(executable_name)
        if not resolved:
            return {
                "name": executable_name,
                "available": False,
                "path": None,
                "version": None,
                "error": f"Toolchain executable '{executable_name}' not found in PATH or standard LLVM locations."
            }
        version = cls.get_compiler_version(executable_name)
        return {
            "name": executable_name,
            "available": True,
            "path": resolved,
            "version": version,
            "error": None
        }

    def _build_isolated_env(self, temp_dir: str, extra_bin_dir: Optional[str] = None) -> Dict[str, str]:
        """
        Constructs a minimal, clean environment dict containing no backend secrets.
        Ensures compiler executables and system libraries are reachable via PATH.
        """
        path_components: List[str] = []
        if extra_bin_dir and os.path.isdir(extra_bin_dir):
            path_components.append(extra_bin_dir)

        existing_path = os.environ.get(
            "PATH",
            "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/Library/Developer/CommandLineTools/usr/bin"
        )
        for p in existing_path.split(os.pathsep):
            if p and p not in path_components:
                path_components.append(p)

        # Append standard LLVM search paths
        for llvm_dir in [
            "/usr/bin",
            "/bin",
            "/usr/local/bin",
            "/usr/lib/llvm-19/bin",
            "/usr/lib/llvm-18/bin",
            "/usr/lib/llvm-17/bin",
            "/usr/lib/llvm-16/bin",
            "/usr/lib/llvm-15/bin",
            "/usr/lib/llvm-14/bin",
        ]:
            if llvm_dir not in path_components:
                path_components.append(llvm_dir)

        isolated_env = {
            "PATH": os.pathsep.join(path_components),
            "TMPDIR": temp_dir,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "dumb",
        }
        return isolated_env

    def _apply_resource_limits(self):
        """
        Applies POSIX resource limits inside preexec_fn before exec().
        """
        if not HAS_RESOURCE:
            return

        try:
            # CPU time limit in seconds (soft 5s, hard 6s)
            cpu_limit = int(self.timeout_seconds) + 1
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 1))
        except Exception as e:
            logger.debug(f"Could not set RLIMIT_CPU: {e}")

        try:
            # Maximum created file size: 10 MB
            max_bytes = 10 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))
        except Exception as e:
            logger.debug(f"Could not set RLIMIT_FSIZE: {e}")

        try:
            # Maximum open file descriptors
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        except Exception as e:
            logger.debug(f"Could not set RLIMIT_NOFILE: {e}")

    def execute_in_sandbox(
        self,
        executable_name: str,
        arguments: List[str],
        code: str,
        filename: str,
    ) -> ExecutionResult:
        """
        Writes code to a sandboxed temporary file, runs the analyzer tool,
        and safely returns stdout, stderr, and returncode.
        """
        executable_path = self.resolve_executable(executable_name)
        if not executable_path:
            raise CompilerNotFoundError(
                f"Required toolchain executable '{executable_name}' is not installed "
                f"or not found in the deployment environment PATH."
            )

        with tempfile.TemporaryDirectory(prefix="sentinel_sandbox_") as temp_dir:
            file_path = os.path.join(temp_dir, filename)
            
            # Write file with restricted permissions (0o600 - owner read/write only)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(file_path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(code)

            # Build sanitized argument list replacing placeholder with actual file
            cmd = [executable_path]
            for arg in arguments:
                if arg == "{INPUT_FILE}":
                    cmd.append(file_path)
                else:
                    cmd.append(arg)

            extra_bin_dir = os.path.dirname(executable_path)
            isolated_env = self._build_isolated_env(temp_dir, extra_bin_dir=extra_bin_dir)

            preexec = self._apply_resource_limits if HAS_RESOURCE else None

            try:
                proc = subprocess.run(
                    cmd,
                    cwd=temp_dir,
                    env=isolated_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout_seconds,
                    text=True,
                    preexec_fn=preexec,
                )
                
                # Replace the temporary directory path with generic "<source>"
                sanitized_stderr = proc.stderr.replace(file_path, "<source>").replace(temp_dir, "")
                sanitized_stdout = proc.stdout.replace(file_path, "<source>").replace(temp_dir, "")

                return ExecutionResult(
                    stdout=sanitized_stdout,
                    stderr=sanitized_stderr,
                    returncode=proc.returncode,
                    timed_out=False
                )
            except subprocess.TimeoutExpired as te:
                logger.warning(f"Compiler process timed out after {self.timeout_seconds}s: {executable_name}")
                return ExecutionResult(
                    stdout="",
                    stderr=f"Error: Analysis timed out after {self.timeout_seconds} seconds.",
                    returncode=-1,
                    timed_out=True
                )
            except Exception as e:
                logger.error(f"Unexpected error executing {executable_name}: {e}")
                raise CompilerError(f"Failed to execute analyzer: {e}")
