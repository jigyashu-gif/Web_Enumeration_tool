import customtkinter as ctk
from tkinter import messagebox


class SettingsPage(ctk.CTkFrame):
    def __init__(self, parent, controller) -> None:
        super().__init__(parent)
        self.controller = controller
        self.settings = controller.get_settings()

        self.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(self, text="Settings", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        form = ctk.CTkFrame(self)
        form.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Default timeout (s)").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.timeout_entry = ctk.CTkEntry(form)
        self.timeout_entry.insert(0, str(self.settings.get("timeout", 5.0)))
        self.timeout_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(form, text="Default threads").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.threads_entry = ctk.CTkEntry(form)
        self.threads_entry.insert(0, str(self.settings.get("threads", 20)))
        self.threads_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(form, text="Theme").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.theme_var = ctk.StringVar(value=self.settings.get("theme", "dark"))
        self.theme_opt = ctk.CTkOptionMenu(form, values=["dark", "light", "system"], variable=self.theme_var)
        self.theme_opt.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        actions = ctk.CTkFrame(self)
        actions.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="ew")

        save_btn = ctk.CTkButton(actions, text="Save Settings", command=self.save)
        save_btn.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        apply_btn = ctk.CTkButton(actions, text="Apply Theme", command=self.apply_theme)
        apply_btn.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        note = ctk.CTkLabel(
            self,
            text="Tip (macOS): always run with the same Python you installed packages into.\nRecommended: `python -m venv .venv` then `source .venv/bin/activate`.",
            justify="left",
        )
        note.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="w")

    def save(self) -> None:
        try:
            timeout = float(self.timeout_entry.get().strip() or "5")
        except ValueError:
            timeout = 5.0
        try:
            threads = int(self.threads_entry.get().strip() or "20")
        except ValueError:
            threads = 20

        threads = max(1, min(500, threads))
        self.settings.set("timeout", timeout)
        self.settings.set("threads", threads)
        self.settings.set("theme", self.theme_var.get())
        messagebox.showinfo("Saved", "Settings saved to config.json")

    def apply_theme(self) -> None:
        ctk.set_appearance_mode(self.theme_var.get())
        messagebox.showinfo("Applied", "Theme applied (restart may improve consistency).")

