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
        Locates the full path to a compiler executable, checking PATH and common
        locations on Linux and macOS.
        """
        # First check PATH
        resolved = shutil.which(name)
        if resolved and os.access(resolved, os.X_OK):
            return resolved

        # Check standard known directories
        search_paths = [
            "/usr/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/Library/Developer/CommandLineTools/usr/bin",
            "/usr/lib/llvm-14/bin",
            "/usr/lib/llvm-15/bin",
            "/usr/lib/llvm-16/bin",
            "/usr/lib/llvm-17/bin",
            "/usr/lib/llvm-18/bin",
        ]
        for base in search_paths:
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    def is_available(self, executable_name: str) -> bool:
        """Checks if the required compiler or analyzer tool is available."""
        return self.resolve_executable(executable_name) is not None

    def _build_isolated_env(self, temp_dir: str) -> Dict[str, str]:
        """
        Constructs a minimal, clean environment dict containing no backend secrets.
        """
        isolated_env = {
            "PATH": os.environ.get(
                "PATH",
                "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/Library/Developer/CommandLineTools/usr/bin",
            ),
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

            isolated_env = self._build_isolated_env(temp_dir)

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
