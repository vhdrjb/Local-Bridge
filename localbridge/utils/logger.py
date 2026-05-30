"""
Logging Setup for LocalBridge.

Configures structured logging with both console and file outputs.
Uses loguru for enhanced formatting, rotation, and filtering.
Access logging is separated from main diagnostic logs for clarity.
"""

import sys
from pathlib import Path
from loguru import logger


def setup_logging(level: str = "INFO", log_file: str = "", access_log: str = "") -> None:
    """Configure the logging subsystem.

    Removes default loguru handlers and installs custom ones:
    - Console handler with colorized, concise format for interactive use.
    - File handler for persistent diagnostic logs (if path provided).
    - Access file handler for connection-level audit trail (if path provided).

    Args:
        level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to the main diagnostic log file. Empty string disables file logging.
        access_log: Path to the access/connection log file. Empty string disables access logging.
    """
    logger.remove()

    # Console handler — compact format for interactive monitoring
    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # Main diagnostic log file — detailed format with timestamps and process info
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_file,
            level=level,
            format=(
                "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
                "{level: <8} | "
                "{name}:{function}:{line} - "
                "{message}"
            ),
            rotation="10 MB",
            retention="7 days",
            compression="gz",
            encoding="utf-8",
        )

    # Access log — one line per connection for auditing and analysis
    if access_log:
        access_path = Path(access_log)
        access_path.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            access_log,
            level="INFO",
            format="{time:YYYY-MM-DD HH:mm:ss} | {message}",
            filter=lambda record: "access_log" in record["extra"],
            rotation="10 MB",
            retention="30 days",
            compression="gz",
            encoding="utf-8",
        )

    logger.info("Logging initialized at level {}", level)


def get_access_logger():
    """Return a logger bound with access_log context.

    Use this for recording connection events that should appear
    in the access log file separate from diagnostic messages.

    Returns:
        A loguru logger instance bound with access_log extra context.
    """
    return logger.bind(access_log=True)
