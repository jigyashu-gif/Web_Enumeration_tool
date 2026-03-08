import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from queue import Queue
from typing import List, Optional, Callable

import httpx


@dataclass
class SubdomainResult:
    hostname: str
    ip: Optional[str]
    http_status: Optional[int]
    reason: str


class SubdomainFuzzer:
    """
    Simple subdomain fuzzer with DNS resolution and optional HTTP check.

    Threading model:
    - ThreadPoolExecutor is used for both DNS lookups and HTTP checks.
    - Results are written to a Queue so the GUI thread can safely consume them.
    """

    def __init__(
        self,
        max_workers: int = 20,
        timeout: float = 5.0,
        http_check: bool = True,
    ) -> None:
        self.max_workers = max_workers
        self.timeout = timeout
        self.http_check = http_check
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def reset_stop_flag(self) -> None:
        self._stop = False

    def _resolve_and_check(self, base_domain: str, sub: str) -> Optional[SubdomainResult]:
        if self._stop:
            return None
        hostname = f"{sub.strip()}.{base_domain}".strip()
        try:
            ip = socket.gethostbyname(hostname)
        except OSError as exc:
            return None

        status = None
        reason = "Resolved"
        if self.http_check:
            url = f"http://{hostname}"
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                    r = client.get(url)
                    status = r.status_code
                    reason = r.reason_phrase
            except httpx.RequestError as exc:
                reason = str(exc)

        return SubdomainResult(hostname=hostname, ip=ip, http_status=status, reason=reason)

    def fuzz(
        self,
        base_domain: str,
        words: List[str],
        result_queue: Queue,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self.reset_stop_flag()

        tasks = [w.strip() for w in words if w.strip()]
        total = len(tasks)
        done = 0

        if total == 0:
            return

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {
                executor.submit(self._resolve_and_check, base_domain, sub): sub for sub in tasks
            }
            for future in as_completed(future_map):
                if self._stop:
                    break
                res = future.result()
                done += 1
                if res:
                    result_queue.put(res)
                if progress_callback:
                    progress_callback(done, total)

