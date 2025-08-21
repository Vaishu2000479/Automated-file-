from __future__ import annotations
import os
from forensic_tool.gui import run_gui
from forensic_tool.logger import get_logger

try:
    # Load environment variables from .env if present
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

logger = get_logger()


def main():
    logger.info("Application started")
    try:
        run_gui()
    finally:
        logger.info("Application exited")


if __name__ == '__main__':
    main()
