"""Password analyzer."""
import re
import math
import hashlib
import requests


def analyze_password(password: str) -> dict:
    if not password:
        return {"error": "empty password"}

    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"\d", password):
        charset += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
        charset += 32

    entropy = math.log2(charset) * len(password) if charset > 1 else 0

    seconds = (2 ** entropy) / 1e10 if entropy < 200 else float("inf")
    if seconds < 1:
        crack = "Instan"
    elif seconds < 60:
        crack = f"{seconds:.1f} detik"
    elif seconds < 3600:
        crack = f"{seconds/60:.1f} menit"
    elif seconds < 86400:
        crack = f"{seconds/3600:.1f} jam"
    elif seconds < 31536000:
        crack = f"{seconds/86400:.1f} hari"
    elif seconds < 1e9:
        crack = f"{seconds/31536000:.1f} tahun"
    else:
        crack = "> 1000 tahun"

    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
    elif len(password) >= 8:
        feedback.append("Gunakan ≥12 karakter untuk keamanan lebih baik")
    else:
        feedback.append("Minimal 8 karakter")

    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Kombinasikan huruf besar + kecil")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Tambahkan angka")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
        score += 1
    else:
        feedback.append("Tambahkan karakter khusus")

    if any(p in password.lower() for p in ["password", "123456", "qwerty", "admin"]):
        score = max(0, score - 2)
        feedback.append("Mengandung pola password umum")

    if score >= 4 and entropy >= 60:
        category = "SANGAT KUAT"
    elif score >= 3 and entropy >= 40:
        category = "SEDANG"
    else:
        category = "LEMAH"

    return {
        "entropy": round(entropy, 2),
        "length": len(password),
        "crack_time": crack,
        "score": score,
        "category": category,
        "feedback": feedback,
    }


def check_hibp(password: str, timeout: int = 8) -> dict:
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        pfx, sfx = sha1[:5], sha1[5:]
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{pfx}", timeout=timeout
        )
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        for line in r.text.splitlines():
            if line.startswith(sfx):
                return {"found": True, "count": line.split(":")[1]}
        return {"found": False, "count": 0}
    except Exception as e:
        return {"error": str(e)}
