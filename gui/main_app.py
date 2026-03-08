import json
import os
import sys
from pathlib import Path
from queue import Queue
from typing import Dict, Any, Type

import customtkinter as ctk

# Allow running as a script on macOS/Windows/Linux:
# `python gui/main_app.py` sets sys.path to the `gui/` folder, breaking
# `import gui...`. This adds the project root back to sys.path.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gui.pages.dashboard import DashboardPage
from gui.pages.dir_page import DirectoryFuzzerPage
from gui.pages.subdomain_page import SubdomainFuzzerPage
from gui.pages.fingerprint_page import FingerprintPage
from gui.pages.vuln_page import VulnerabilityPage
from gui.pages.settings_page import SettingsPage
from gui.pages.results_viewer import ResultsViewerPage


CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")


class SettingsManager:
    DEFAULTS: Dict[str, Any] = {
        "timeout": 5.0,
        "threads": 20,
        "theme": "dark",
    }

    def __init__(self, path: str = CONFIG_PATH) -> None:
        self.path = path
        self.data: Dict[str, Any] = dict(self.DEFAULTS)
        self.load()

    def load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                self.data.update(loaded)
            except Exception:
                pass

    def save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception:
            pass

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.save()


class MainApp(ctk.CTk):
    """
    Main CustomTkinter application with sidebar navigation.
    """

    PAGES: Dict[str, Type[ctk.CTkFrame]] = {
        "Dashboard": DashboardPage,
        "Directory Fuzzer": DirectoryFuzzerPage,
        "Subdomain Fuzzer": SubdomainFuzzerPage,
        "Fingerprinting": FingerprintPage,
        "Vulnerability Scanner": VulnerabilityPage,
        "Settings": SettingsPage,
        "Results Viewer": ResultsViewerPage,
    }

    def __init__(self) -> None:
        self.settings = SettingsManager()
        ctk.set_appearance_mode(self.settings.get("theme", "dark"))
        ctk.set_default_color_theme("blue")

        super().__init__()
        self.title("Web Enumeration Tool")
        self.geometry("1100x700")

        self._result_queues: Dict[str, Queue] = {}
        self.results_store: Dict[str, list] = {}

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_rowconfigure(len(self.PAGES) + 1, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="Web Enum", font=ctk.CTkFont(size=18, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.buttons: Dict[str, ctk.CTkButton] = {}
        row = 1
        for name in self.PAGES.keys():
            btn = ctk.CTkButton(self.sidebar, text=name, command=lambda n=name: self.show_page(n))
            btn.grid(row=row, column=0, padx=10, pady=5, sticky="ew")
            self.buttons[name] = btn
            row += 1

        # Main container
        self.container = ctk.CTkFrame(self)
        self.container.grid(row=0, column=1, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # Instantiate all pages once so dashboard can trigger them
        self.pages_instances: Dict[str, ctk.CTkFrame] = {}
        for name, page_class in self.PAGES.items():
            frame = page_class(self.container, self)
            frame.grid(row=0, column=0, sticky="nsew")
            self.pages_instances[name] = frame

        self.show_page("Dashboard")

    def get_settings(self) -> SettingsManager:
        return self.settings

    def show_page(self, name: str) -> None:
        page = self.pages_instances[name]
        page.tkraise()

    def get_page(self, name: str) -> ctk.CTkFrame:
        return self.pages_instances[name]

    def run_all_modules(self, target: str) -> None:
        """
        Trigger a quick run of all modules from the dashboard.
        `target` may be a full URL or bare domain.
        """
        from urllib.parse import urlparse

        raw = target.strip()
        if not raw:
            return

        if "://" in raw:
            parsed = urlparse(raw)
            base_url = raw
            domain = parsed.hostname or raw
        else:
            domain = raw
            base_url = f"http://{raw}"

        dir_page = self.get_page("Directory Fuzzer")
        sub_page = self.get_page("Subdomain Fuzzer")
        fp_page = self.get_page("Fingerprinting")
        vuln_page = self.get_page("Vulnerability Scanner")

        # Set text fields and trigger their actions
        if hasattr(dir_page, "url_entry"):
            dir_page.url_entry.delete(0, "end")
            dir_page.url_entry.insert(0, base_url)
            dir_page.start()

        if hasattr(sub_page, "domain_entry"):
            sub_page.domain_entry.delete(0, "end")
            sub_page.domain_entry.insert(0, domain)
            sub_page.start()

        if hasattr(fp_page, "url_entry"):
            fp_page.url_entry.delete(0, "end")
            fp_page.url_entry.insert(0, base_url)
            fp_page.run()

        if hasattr(vuln_page, "url_entry"):
            vuln_page.url_entry.delete(0, "end")
            vuln_page.url_entry.insert(0, base_url)
            vuln_page.run()


def run() -> None:
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    run()

