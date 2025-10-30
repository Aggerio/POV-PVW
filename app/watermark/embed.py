"""Embedder utilities.

Provides deterministic, seed-aware embedding for Variant A while keeping
backward-compatible helpers used by the current app/main.py.
"""

import secrets, hashlib
from typing import Tuple


def _tag_from_key(key: bytes) -> str:
    """Derive a short, deterministic tag from the seed/key."""
    return hashlib.sha256(key).hexdigest()[:16]


def embed_with_key(text: str, key: bytes) -> Tuple[str, str]:
    """Embed using a deterministic key.

    Returns: (watermarked_text, tag_hex)
    """
    tag = _tag_from_key(key)
    zwsp = "\u200b"
    watermarked = f"{text}{zwsp}[wm:{tag}]"
    return watermarked, tag


# --- Backward-compatible function (used by current endpoints) ---
def embed_text(text: str, server_salt: bytes) -> Tuple[str, str, str]:
    """Legacy embed: generate a random seed and compute a commitment externally.

    Retained for compatibility until /issue is refactored to pass a derived key.
    Returns: (watermarked, commitment, seed_hex)
    Note: commitment computed here as sha256(server_salt + seed) for legacy flow.
    """
    seed = secrets.token_bytes(16)
    tag = _tag_from_key(seed)
    zwsp = "\u200b"
    watermarked = f"{text}{zwsp}[wm:{tag}]"
    # legacy commitment scheme (server_salt prefixed)
    commitment = hashlib.sha256(server_salt + seed).hexdigest()
    return watermarked, commitment, seed.hex()
