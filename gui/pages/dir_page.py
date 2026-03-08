import os
import threading
from queue import Queue, Empty
from typing import Optional, List

import customtkinter as ctk
from tkinter import filedialog, messagebox

from core.directory_fuzzer import DirectoryFuzzer, FuzzResult


class DirectoryFuzzerPage(ctk.CTkFrame):
    """
    GUI wrapper for DirectoryFuzzer.

    Threading decision:
    - The fuzzer runs in a background thread to keep the Tk GUI responsive.
    - Worker threads do the HTTP I/O; results are passed to the GUI via Queue.
    """

    def __init__(self, parent, controller) -> None:
        super().__init__(parent)
        self.controller = controller

        self.result_queue: Queue = Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._fuzzer: Optional[DirectoryFuzzer] = None
        self._wordlist: List[str] = []

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(1, weight=1)

        title = ctk.CTkLabel(self, text="Directory Fuzzer", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, columnspan=3, padx=20, pady=(20, 10), sticky="w")

        self.url_entry = ctk.CTkEntry(self, placeholder_text="Target URL (e.g., https://example.com)")
        self.url_entry.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.wordlist_btn = ctk.CTkButton(self, text="Select Wordlist", command=self.select_wordlist)
        self.wordlist_btn.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        self.start_btn = ctk.CTkButton(self, text="Start", command=self.start)
        self.start_btn.grid(row=1, column=2, padx=20, pady=10, sticky="e")

        opts = ctk.CTkFrame(self)
        opts.grid(row=2, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="ew")
        opts.grid_columnconfigure(7, weight=1)

        ctk.CTkLabel(opts, text="Threads").grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")
        self.threads_entry = ctk.CTkEntry(opts, width=80)
        self.threads_entry.insert(0, str(self.controller.get_settings().get("threads", 20)))
        self.threads_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w")

        ctk.CTkLabel(opts, text="Timeout (s)").grid(row=0, column=2, padx=(15, 5), pady=10, sticky="w")
        self.timeout_entry = ctk.CTkEntry(opts, width=80)
        self.timeout_entry.insert(0, str(self.controller.get_settings().get("timeout", 5.0)))
        self.timeout_entry.grid(row=0, column=3, padx=5, pady=10, sticky="w")

        ctk.CTkLabel(opts, text="Depth").grid(row=0, column=4, padx=(15, 5), pady=10, sticky="w")
        self.depth_entry = ctk.CTkEntry(opts, width=60)
        self.depth_entry.insert(0, "3")
        self.depth_entry.grid(row=0, column=5, padx=5, pady=10, sticky="w")

        ctk.CTkLabel(opts, text="Status filter (e.g. 200,301)").grid(row=0, column=6, padx=(15, 5), pady=10, sticky="w")
        self.status_entry = ctk.CTkEntry(opts)
        self.status_entry.insert(0, "200,204,301,302,307,308,401,403")
        self.status_entry.grid(row=0, column=7, padx=5, pady=10, sticky="ew")

        self.stop_btn = ctk.CTkButton(opts, text="Stop", fg_color="#8b1e1e", command=self.stop)
        self.stop_btn.grid(row=0, column=8, padx=10, pady=10, sticky="e")

        self.progress = ctk.CTkProgressBar(self)
        self.progress.set(0.0)
        self.progress.grid(row=3, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="ew")

        self.output = ctk.CTkTextbox(self)
        self.output.grid(row=4, column=0, columnspan=3, padx=20, pady=(0, 20), sticky="nsew")

        # Load default wordlist (SecLists-inspired) if present
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        default_path = os.path.join(project_root, "wordlists", "common_dirs.txt")
        if os.path.exists(default_path):
            try:
                with open(default_path, "r", encoding="utf-8", errors="ignore") as f:
                    self._wordlist = [line.strip() for line in f if line.strip()]
                self._log(f"Loaded default wordlist from {default_path} ({len(self._wordlist)} entries)\n")
            except Exception:
                pass

        self.after(100, self._poll_queue)

    def select_wordlist(self) -> None:
        path = filedialog.askopenfilename(title="Select wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self._wordlist = [line.strip() for line in f if line.strip()]
            self._log(f"Loaded wordlist: {path} ({len(self._wordlist)} entries)\n")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to load wordlist:\n{exc}")

    def _parse_status_filter(self) -> Optional[List[int]]:
        raw = self.status_entry.get().strip()
        if not raw:
            return None
        out: List[int] = []
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                out.append(int(part))
        return out or None

    def start(self) -> None:
        if self._worker_thread and self._worker_thread.is_alive():
            messagebox.showinfo("Running", "Directory fuzzing is already running.")
            return

        base_url = self.url_entry.get().strip()
        if not base_url:
            messagebox.showerror("Missing input", "Please enter a target URL.")
            return
        if not self._wordlist:
            messagebox.showerror("Missing input", "Please select a wordlist.")
            return

        try:
            threads = max(1, min(500, int(self.threads_entry.get().strip() or "20")))
        except ValueError:
            threads = 20
        try:
            timeout = float(self.timeout_entry.get().strip() or "5")
        except ValueError:
            timeout = 5.0
        try:
            depth = max(1, int(self.depth_entry.get().strip() or "3"))
        except ValueError:
            depth = 3

        status_filter = self._parse_status_filter()

        self.progress.set(0.0)
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self._log("Starting directory fuzz...\n")

        self._fuzzer = DirectoryFuzzer(max_workers=threads, timeout=timeout, status_filter=status_filter)

        def progress_cb(done: int, total: int) -> None:
            self.result_queue.put(("__progress__", done, total))

        def runner() -> None:
            assert self._fuzzer is not None
            self._fuzzer.fuzz(
                base_url=base_url,
                paths=self._wordlist,
                max_depth=depth,
                result_queue=self.result_queue,
                progress_callback=progress_cb,
            )
            self.result_queue.put(("__done__",))

        self._worker_thread = threading.Thread(target=runner, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        if self._fuzzer:
            self._fuzzer.stop()
            self._log("Stop requested...\n")

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self.result_queue.get_nowait()
                if isinstance(item, tuple) and item and item[0] == "__progress__":
                    _, done, total = item
                    self.progress.set(done / max(total, 1))
                elif isinstance(item, tuple) and item and item[0] == "__done__":
                    self._log("\nDone.\n")
                elif isinstance(item, FuzzResult):
                    self._log(self._format_result(item))
                else:
                    # ignore unknown
                    pass
        except Empty:
            pass
        self.after(150, self._poll_queue)

    @staticmethod
    def _format_result(res: FuzzResult) -> str:
        code = res.status_code if res.status_code is not None else "ERR"
        return f"[{code}] (depth {res.depth}) {res.url} {res.reason}\n"

    def _log(self, msg: str) -> None:
        self.output.insert("end", msg)
        self.output.see("end")

