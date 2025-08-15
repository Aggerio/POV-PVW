# Demo embedder: appends an invisible tag (seed-based) to text.
# Replace with a real watermark module in production.
import os, secrets, hashlib
from typing import Tuple

def _derive_commitment(seed: bytes, server_salt: bytes)->str:
    return hashlib.sha256(server_salt + seed).hexdigest()

def _make_tag(seed: bytes)->str:
    # create a short hex tag
    return hashlib.sha256(seed).hexdigest()[:16]

def embed_text(text: str, server_salt: bytes)->Tuple[str, str, str]:
    seed = secrets.token_bytes(16)
    commitment = _derive_commitment(seed, server_salt)
    tag = _make_tag(seed)
    # simple demo watermark: append zero-width space + tag
    zwsp = "\u200b"
    watermarked = f"{text}{zwsp}[wm:{tag}]"
    # store minimal metadata (in a real system, seed never leaves TEE)
    seed_b64 = seed.hex()
    return watermarked, commitment, seed_b64
