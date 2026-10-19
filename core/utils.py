"""Helper umum."""
import json
import urllib.parse


def clean_target(target: str) -> str:
    return (target.replace("https://", "").replace("http://", "")
            .split("/")[0].split(":")[0].strip())


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def to_json(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
