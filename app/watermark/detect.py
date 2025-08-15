# Demo detector: checks presence of a seed-derived tag pattern.
# Replace with a real detector. Uses commitment to validate seed link.
import hashlib, binascii

def _derive_commitment(seed_hex: str, server_salt: bytes)->str:
    seed = bytes.fromhex(seed_hex)
    return hashlib.sha256(server_salt + seed).hexdigest()

def _make_tag(seed_hex: str)->str:
    seed = bytes.fromhex(seed_hex)
    return hashlib.sha256(seed).hexdigest()[:16]

def detect_text(content: str, commitment: str, server_salt: bytes):
    # brute small search space? here we require the seed to be recoverable from log, not guessed.
    # For demo we'll look for tag pattern already embedded and trust commitment matched via log.
    # Statistic = 1.0 if exact tag present else 0.0; p-value dummy.
    # In a real system, compute z-score or p-value of watermark statistic.
    return {"statistic": 1.0 if "[wm:" in content else 0.0, "pvalue": 0.01 if "[wm:" in content else 1.0}
