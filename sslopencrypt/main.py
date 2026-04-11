#!/usr/bin/env python3
"""
sslOpenCrypt — main entry point.

Usage:
  python main.py          → Launch GUI
  python main.py --cli … → Headless CLI mode (see cli/main.py --help)
"""

import sys
import os

# Add the sslopencrypt directory to sys.path so all imports resolve
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    if "--cli" in sys.argv:
        # Strip --cli flag and hand off to CLI
        sys.argv.remove("--cli")
        from cli.main import main as cli_main
        cli_main()
    else:
        # GUI mode
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            print(
                "ERROR: PyQt6 is not installed.\n"
                "Install it with: pip install PyQt6\n"
                "Or install all dependencies: pip install -r requirements.txt",
                file=sys.stderr,
            )
            sys.exit(1)

        from ui.main_window import run_app
        sys.exit(run_app())


if __name__ == "__main__":
    main()
