"""HTTP client dengan retry + SSL fallback."""
import time
import requests
import urllib3
from core.config import DEFAULT_TIMEOUT
from core.database import log_event

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPEngine:
    def __init__(self, timeout=DEFAULT_TIMEOUT,
                 user_agent="Mozilla/5.0 (CyberShield v5)"):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def get(self, url, verify=True, allow_redirects=True, retries=2, **kw):
        last_err = None
        for attempt in range(retries + 1):
            try:
                return self.session.get(
                    url, timeout=self.timeout, verify=verify,
                    allow_redirects=allow_redirects, **kw,
                )
            except requests.exceptions.SSLError:
                raise
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                last_err = e
                if attempt < retries:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                raise
        raise last_err

    def safe_get(self, url, ignore_ssl=False, **kw):
        try:
            return self.get(url, verify=not ignore_ssl, **kw), True, None
        except requests.exceptions.SSLError as e:
            if ignore_ssl:
                raise
            log_event("ssl_fallback", url)
            return self.get(url, verify=False, **kw), False, str(e)
