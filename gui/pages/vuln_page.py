import threading
from typing import Optional

import customtkinter as ctk
from tkinter import messagebox

from core.vuln_scanner import SimpleVulnScanner, VulnScanResult, VulnFinding


class VulnerabilityPage(ctk.CTkFrame):
    def __init__(self, parent, controller) -> None:
        super().__init__(parent)
        self.controller = controller
        self._worker: Optional[threading.Thread] = None

        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(self, text="Simple Vulnerability Scanner", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        self.url_entry = ctk.CTkEntry(self, placeholder_text="Target URL (e.g., https://example.com)")
        self.url_entry.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        actions = ctk.CTkFrame(self)
        actions.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(actions, text="Timeout (s)").grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")
        self.timeout_entry = ctk.CTkEntry(actions, width=80)
        self.timeout_entry.insert(0, str(self.controller.get_settings().get("timeout", 5.0)))
        self.timeout_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w")

        self.run_btn = ctk.CTkButton(actions, text="Scan", command=self.run)
        self.run_btn.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        self.output = ctk.CTkTextbox(self)
        self.output.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")

    def run(self) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("Running", "Scan is already running.")
            return

        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Missing input", "Please enter a target URL.")
            return

        try:
            timeout = float(self.timeout_entry.get().strip() or "5")
        except ValueError:
            timeout = 5.0

        self.output.delete("1.0", "end")
        self.output.insert("end", "Running safe checks...\n\n")

        def worker() -> None:
            scanner = SimpleVulnScanner(timeout=timeout)
            result = scanner.scan(url)
            self.after(0, lambda: self._render(result))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _render(self, r: VulnScanResult) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("end", f"URL: {r.url}\n")
        self.output.insert("end", f"Status: {r.status_code}\n\n")
        if not r.findings:
            self.output.insert("end", "No findings from the enabled checks.\n")
            return

        self.output.insert("end", "Findings:\n")
        for f in r.findings:
            self.output.insert("end", f"\n[{f.category}] {f.description}\nEvidence: {f.evidence}\n")

