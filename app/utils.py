import hashlib, hmac, os, json, time
from typing import Dict, Any

SECRET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "secret.key")

def ensure_secret()->bytes:
    os.makedirs(os.path.dirname(SECRET_PATH), exist_ok=True)
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "wb") as f:
            f.write(os.urandom(32))
    with open(SECRET_PATH, "rb") as f:
        return f.read()

def sha256_hex(data: bytes)->str:
    return hashlib.sha256(data).hexdigest()

def leading_zeros_bits(hex_hash: str)->int:
    bits = bin(int(hex_hash, 16))[2:].zfill(256)
    return len(bits) - len(bits.lstrip('0'))

def hmac_sign(payload: Dict[str, Any])->str:
    secret = ensure_secret()
    msg = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def now_ms()->int:
    return int(time.time() * 1000)
