from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import hashlib

import httpx
from bs4 import BeautifulSoup  # type: ignore


@dataclass
class FingerprintResult:
    url: str
    status_code: Optional[int]
    title: str = ""
    server: str = ""
    x_powered_by: str = ""
    technologies: List[str] = field(default_factory=list)
    cms: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body_hash: Optional[str] = None


class Fingerprinter:
    """
    Performs very lightweight fingerprinting using headers and HTML content.

    Async vs sync:
    - This module uses a simple synchronous httpx.Client as the operation
      typically targets a single URL and does not benefit much from asyncio.
    """

    CMS_SIGNATURES = {
        "wordpress": ["wp-content", "wp-includes"],
        "joomla": ["Joomla!", "com_content"],
        "drupal": ["Drupal.settings", "sites/all/"],
    }

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def analyze(self, url: str) -> FingerprintResult:
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                r = client.get(url)
        except httpx.RequestError as exc:
            return FingerprintResult(url=url, status_code=None, title=str(exc))

        headers = {k.lower(): v for k, v in r.headers.items()}
        server = headers.get("server", "")
        x_powered_by = headers.get("x-powered-by", "")

        html = r.text or ""
        title = ""
        technologies: List[str] = []
        cms: Optional[str] = None

        try:
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()

            # Meta tags and scripts for rough technology hints
            for meta in soup.find_all("meta"):
                content = " ".join(filter(None, [meta.get("name"), meta.get("content")]))
                if content:
                    technologies.append(content)
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    technologies.append(src)
        except Exception:
            pass

        # Simple CMS detection
        lowered = html.lower()
        for name, sigs in self.CMS_SIGNATURES.items():
            if any(sig.lower() in lowered for sig in sigs):
                cms = name
                break

        body_hash = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()

        return FingerprintResult(
            url=url,
            status_code=r.status_code,
            title=title,
            server=server,
            x_powered_by=x_powered_by,
            technologies=list(dict.fromkeys(technologies))[:50],
            cms=cms,
            headers=headers,
            body_hash=body_hash,
        )

