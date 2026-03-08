import customtkinter as ctk
from tkinter import messagebox


class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, controller) -> None:
        super().__init__(parent)
        self.controller = controller

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        label = ctk.CTkLabel(
            self,
            text="Web Enumeration Dashboard",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="nw")

        self.target_entry = ctk.CTkEntry(
            self,
            placeholder_text="Target (URL or domain, e.g. https://example.com or example.com)",
        )
        self.target_entry.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")

        run_all_btn = ctk.CTkButton(self, text="Run All Modules", command=self._run_all)
        run_all_btn.grid(row=1, column=1, padx=20, pady=(0, 10), sticky="e")

        info = (
            "One-click mode:\n"
            "- Uses default wordlists (SecLists-inspired) for directory and subdomain fuzzing.\n"
            "- Runs Directory Fuzzer, Subdomain Fuzzer, Fingerprinting, and Vulnerability Scanner in parallel.\n\n"
            "You can also fine-tune each module from the sidebar pages.\n"
        )

        text = ctk.CTkTextbox(self, height=200)
        text.insert("1.0", info)
        text.configure(state="disabled")
        text.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")

    def _run_all(self) -> None:
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Missing target", "Please enter a URL or domain to scan.")
            return
        self.controller.run_all_modules(target)

