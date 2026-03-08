"""
Project entrypoint (macOS/Windows/Linux friendly).

Running a package module as a script (e.g. `python gui/main_app.py`) can break
absolute imports like `from gui.pages...` because Python changes sys.path.

This file avoids that by running the app from the project root.
"""

from gui.main_app import run


if __name__ == "__main__":
    run()

