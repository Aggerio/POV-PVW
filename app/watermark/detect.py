"""Detector utilities.

Seed-aware detector for Variant A, plus legacy detector kept for compatibility.
"""

import hashlib


def _tag_from_key(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def detect_with_key(content: str, key: bytes):
    """Deterministically detect watermark by recomputing expected tag.

    Returns: { statistic: float, pvalue: float, present: bool }
    """
    tag = _tag_from_key(key)
    present = f"[wm:{tag}]" in content
    return {
        "statistic": 1.0 if present else 0.0,
        "pvalue": 0.01 if present else 1.0,
        "present": present,
    }


# --- Backward-compatible detector (used by current endpoints) ---
def detect_text(content: str, commitment: str, server_salt: bytes):
    # Legacy detector cannot recover the seed; it only checks the pattern exists.
    present = "[wm:" in content
    return {"statistic": 1.0 if present else 0.0, "pvalue": 0.01 if present else 1.0}
