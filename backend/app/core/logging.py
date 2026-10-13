import logging
import sys
import re

SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|password|secret|token|authorization)\s*[:=]\s*["\']?([^"\'\s]+)["\']?')
]


class SanitizingFormatter(logging.Formatter):
    """Custom formatter that automatically masks API keys and tokens in log messages."""
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in SENSITIVE_PATTERNS:
            msg = pattern.sub(r'\1=***REDACTED***', msg)
        return msg


def setup_logging():
    logger = logging.getLogger("sentinelcode")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers on reload
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = SanitizingFormatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()
