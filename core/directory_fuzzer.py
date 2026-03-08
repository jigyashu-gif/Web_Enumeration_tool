import httpx
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class FuzzResult:
    url: str
    status_code: Optional[int]
    reason: str
    depth: int


class DirectoryFuzzer:
    """
    Layer-based directory fuzzer.

    Threading model:
    - We use ThreadPoolExecutor for I/O-bound HTTP requests.
    - Results are pushed into a Queue to allow thread-safe consumption
      by the GUI thread (Tkinter / CustomTkinter must only be touched
      from the main thread).
    """

    def __init__(
        self,
        max_workers: int = 20,
        timeout: float = 5.0,
        status_filter: Optional[List[int]] = None,
        rate_limit_delay: float = 0.0,
    ) -> None:
        self.max_workers = max_workers
        self.timeout = timeout
        self.status_filter = status_filter
        self.rate_limit_delay = rate_limit_delay
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def stop(self) -> None:
        self._stop_event.set()

    def reset_stop_flag(self) -> None:
        self._stop_event.clear()

    def _should_stop(self) -> bool:
        return self._stop_event.is_set()

    def _request_url(self, client: httpx.Client, url: str, depth: int) -> Optional[FuzzResult]:
        if self._should_stop():
            return None
        try:
            resp = client.get(url, timeout=self.timeout, follow_redirects=True)
            status = resp.status_code
            if self.status_filter and status not in self.status_filter:
                return None
            return FuzzResult(url=url, status_code=status, reason=resp.reason_phrase, depth=depth)
        except httpx.RequestError as exc:
            return FuzzResult(url=url, status_code=None, reason=str(exc), depth=depth)

    def fuzz(
        self,
        base_url: str,
        paths: List[str],
        max_depth: int,
        result_queue: Queue,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Start fuzzing directories.

        - `base_url`: target base URL (e.g., https://example.com)
        - `paths`: wordlist entries (relative paths)
        - `max_depth`: how deep to build layered paths
        - `result_queue`: thread-safe queue to push FuzzResult objects
        - `progress_callback`: optional callable(total_done, total_tasks)
        """
        self.reset_stop_flag()

        # Pre-build layered paths up to max_depth
        layered_urls = []
        for path in paths:
            # Normalize path (strip leading/trailing slashes)
            clean = path.strip().strip("/")
            if not clean:
                continue
            parts = clean.split("/")
            for depth in range(1, min(len(parts), max_depth) + 1):
                partial = "/".join(parts[:depth])
                url = base_url.rstrip("/") + "/" + partial
                layered_urls.append((url, depth))

        total_tasks = len(layered_urls)
        done = 0

        if total_tasks == 0:
            return

        with httpx.Client(http2=True, verify=False) as client:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_url = {
                    executor.submit(self._request_url, client, url, depth): (url, depth)
                    for url, depth in layered_urls
                }

                for future in as_completed(future_to_url):
                    if self._should_stop():
                        break

                    res = future.result()
                    with self._lock:
                        done += 1
                    if res:
                        result_queue.put(res)

                    if progress_callback:
                        progress_callback(done, total_tasks)

