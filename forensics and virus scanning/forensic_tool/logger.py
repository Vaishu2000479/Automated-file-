import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from .constants import LOG_DIR, LOG_FILE, APP_NAME

_logger = None


def get_logger() -> logging.Logger:
    global _logger
    if _logger:
        return _logger

    log_dir = Path(LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / LOG_FILE

    logger = logging.getLogger(APP_NAME)
    # Increase verbosity for richer diagnostics
    logger.setLevel(logging.DEBUG)

    # Detailed formatter with module, function and line number
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s %(module)s.%(funcName)s:%(lineno)d [%(threadName)s]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_handler = RotatingFileHandler(str(log_path), maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    _logger = logger
    return logger
