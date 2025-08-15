from .utils import sha256_hex, leading_zeros_bits

def validate_pow(client_id: str, endpoint: str, body_hash: str, nonce: str, difficulty: int)->bool:
    material = f"{client_id}|{endpoint}|{body_hash}|{nonce}".encode()
    h = sha256_hex(material)
    return leading_zeros_bits(h) >= difficulty
