from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlencode, urljoin

import httpx
from bs4 import BeautifulSoup  # type: ignore


@dataclass
class VulnFinding:
    category: str
    description: str
    evidence: str


@dataclass
class VulnScanResult:
    url: str
    status_code: Optional[int]
    findings: List[VulnFinding] = field(default_factory=list)


class SimpleVulnScanner:
    """
    Very lightweight and safe vulnerability scanner.

    Only performs:
    - Directory listing detection
    - Reflected XSS probe
    - Basic SQL error-based detection
    - Security header checks
    - robots.txt presence
    - .git exposure check

    All checks are read-only and non-destructive.
    """

    SQL_ERROR_PATTERNS = [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "sql syntax error",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "odbc microsoft access driver",
    ]

    XSS_PAYLOAD = "<script>alert('xss')</script>"

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def scan(self, url: str) -> VulnScanResult:
        findings: List[VulnFinding] = []
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                r = client.get(url)
        except httpx.RequestError as exc:
            return VulnScanResult(url=url, status_code=None, findings=[VulnFinding(
                category="network",
                description="Request failed",
                evidence=str(exc),
            )])

        body = r.text or ""
        status = r.status_code

        # Directory listing
        if self._looks_like_directory_listing(body):
            findings.append(
                VulnFinding(
                    category="directory_listing",
                    description="Possible open directory listing detected.",
                    evidence="Index of / present with file listing.",
                )
            )

        # Basic SQL error-based detection
        lowered = body.lower()
        for pattern in self.SQL_ERROR_PATTERNS:
            if pattern in lowered:
                findings.append(
                    VulnFinding(
                        category="sql_error",
                        description="Potential SQL error-based issue detected.",
                        evidence=pattern,
                    )
                )
                break

        # Simple reflected XSS check (GET parameter reflection)
        xss_url = self._build_query_url(url, {"xss_test": self.XSS_PAYLOAD})
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                xr = client.get(xss_url)
                if self.XSS_PAYLOAD in xr.text:
                    findings.append(
                        VulnFinding(
                            category="xss",
                            description="Reflected XSS pattern appears in response.",
                            evidence="Payload reflected unencoded in response.",
                        )
                    )
        except httpx.RequestError:
            pass

        # Security headers
        security_headers = {
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "strict-transport-security": "HSTS",
        }
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        for key, name in security_headers.items():
            if key not in headers_lower:
                findings.append(
                    VulnFinding(
                        category="security_header",
                        description=f"Missing security header: {name}",
                        evidence=f"{name} not present in response headers.",
                    )
                )

        # robots.txt
        robots_url = urljoin(url, "/robots.txt")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                rr = client.get(robots_url)
                if rr.status_code == 200:
                    findings.append(
                        VulnFinding(
                            category="robots",
                            description="robots.txt discovered.",
                            evidence=f"robots.txt status: {rr.status_code}",
                        )
                    )
        except httpx.RequestError:
            pass

        # .git exposure
        git_url = urljoin(url, "/.git/HEAD")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                gr = client.get(git_url)
                if gr.status_code == 200 and "refs/heads" in gr.text:
                    findings.append(
                        VulnFinding(
                            category=".git",
                            description="Possible exposed .git repository.",
                            evidence=".git/HEAD readable and contains refs.",
                        )
                    )
        except httpx.RequestError:
            pass

        return VulnScanResult(url=url, status_code=status, findings=findings)

    @staticmethod
    def _looks_like_directory_listing(body: str) -> bool:
        lowered = body.lower()
        if "index of /" in lowered and "<title>index of" in lowered:
            return True
        try:
            soup = BeautifulSoup(body, "html.parser")
            if soup.title and "index of" in soup.title.text.lower():
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _build_query_url(base: str, params: Dict[str, str]) -> str:
        if "?" in base:
            return f"{base}&{urlencode(params)}"
        return f"{base}?{urlencode(params)}"

