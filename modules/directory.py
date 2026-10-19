"""Directory brute-forcer."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import DIRECTORY_WORDLIST


def _check(engine, base, path, ignore_ssl):
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = engine.get(url, verify=not ignore_ssl,
                       allow_redirects=False, retries=0)
        if r.status_code < 400:
            return {"path": path, "status": r.status_code, "size": len(r.content)}
    except Exception:
        pass
    return None


def brute_directory(engine, base_url: str, wordlist: list = None,
                    ignore_ssl: bool = False, max_workers: int = 15) -> dict:
    base = base_url.rstrip("/")
    wl = wordlist or DIRECTORY_WORDLIST
    hits = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check, engine, base, p, ignore_ssl): p for p in wl}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                hits.append(r)

    hits.sort(key=lambda x: (x["status"], x["path"]))
    return {"base_url": base, "hits": hits, "total": len(hits), "scanned": len(wl)}
