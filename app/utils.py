import hashlib, hmac, os, json, time, base64
from typing import Dict, Any

# Paths for locally persisted secrets (if env vars are not provided)
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Deprecated: single secret file previously used for both HMAC and salt
SECRET_PATH = os.path.join(DATA_DIR, "secret.key")

# New: separate salt and HMAC key files
SERVER_SALT_PATH = os.path.join(DATA_DIR, "server_salt.bin")
SERVER_KEY_PATH = os.path.join(DATA_DIR, "hmac.key")

try:
    # Prefer cryptography when available (for HKDF)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except Exception:
    HKDF = None  # type: ignore
    hashes = None  # type: ignore


# --- Canonicalization & hashing helpers ---
def canonical_json(obj: Any) -> bytes:
    """Canonical JSON bytes for deterministic hashing/signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leading_zeros_bits(hex_hash: str) -> int:
    bits = bin(int(hex_hash, 16))[2:].zfill(256)
    return len(bits) - len(bits.lstrip('0'))


def now_ms() -> int:
    return int(time.time() * 1000)


# --- Secrets management ---
def _read_env_bytes(var_name: str) -> bytes | None:
    val = os.getenv(var_name)
    if not val:
        return None
    # Try hex, then base64, else raw utf-8
    try:
        return bytes.fromhex(val)
    except Exception:
        pass
    try:
        return base64.b64decode(val)
    except Exception:
        pass
    return val.encode("utf-8")


def get_server_salt() -> bytes:
    """Get server salt for HKDF and commitment. Stable and secret.

    Priority: env SERVER_SALT (hex/base64/raw) -> file server_salt.bin -> generate new.
    """
    b = _read_env_bytes("SERVER_SALT")
    if b:
        return b
    if not os.path.exists(SERVER_SALT_PATH):
        with open(SERVER_SALT_PATH, "wb") as f:
            f.write(os.urandom(32))
    with open(SERVER_SALT_PATH, "rb") as f:
        return f.read()


def get_server_key() -> bytes:
    """Get HMAC signing key. Separate from salt."""
    b = _read_env_bytes("SERVER_KEY")
    if b:
        return b
    if not os.path.exists(SERVER_KEY_PATH):
        with open(SERVER_KEY_PATH, "wb") as f:
            f.write(os.urandom(32))
    with open(SERVER_KEY_PATH, "rb") as f:
        return f.read()


# Backward-compat: legacy secret used previously.
def ensure_secret() -> bytes:
    os.makedirs(os.path.dirname(SECRET_PATH), exist_ok=True)
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "wb") as f:
            f.write(os.urandom(32))
    with open(SECRET_PATH, "rb") as f:
        return f.read()


# --- HKDF (seed derivation) ---
def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256; requires cryptography package."""
    if HKDF is None or hashes is None:
        raise RuntimeError("cryptography is required for HKDF; please install the 'cryptography' package")
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hk.derive(ikm)


# --- HMAC signing ---
def hmac_sign_bytes(key: bytes, payload_bytes: bytes) -> str:
    return hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()


def hmac_sign(payload: Dict[str, Any]) -> str:
    key = get_server_key()
    msg = canonical_json(payload)
    return hmac_sign_bytes(key, msg)
