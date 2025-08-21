import os

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

from forensic_tool.gui import run_gui


if __name__ == "__main__":
    raise SystemExit(run_gui())
