import customtkinter as ctk


class ResultsViewerPage(ctk.CTkFrame):
    """
    Minimal results viewer placeholder.
    (Full export + per-module results aggregation will be added next.)
    """

    def __init__(self, parent, controller) -> None:
        super().__init__(parent)
        self.controller = controller

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(self, text="Results Viewer", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        self.output = ctk.CTkTextbox(self)
        self.output.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

        self.refresh()

    def refresh(self) -> None:
        store = getattr(self.controller, "results_store", {})
        self.output.delete("1.0", "end")
        if not store:
            self.output.insert("end", "No stored results yet. Run a module to generate results.\n")
            return

        for module, items in store.items():
            self.output.insert("end", f"\n== {module} ({len(items)}) ==\n")
            for it in items[:200]:
                self.output.insert("end", f"{it}\n")

