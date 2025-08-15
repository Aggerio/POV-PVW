from app.pow import validate_pow
from app.utils import sha256_hex, leading_zeros_bits

def test_pow():
    client_id = "test"
    endpoint = "/issue"
    body_hash = "00"*32
    # find a nonce with at least 8 leading zeros bits (simple test)
    difficulty = 8
    nonce = 0
    while True:
        h = sha256_hex(f"{client_id}|{endpoint}|{body_hash}|{nonce}".encode())
        if leading_zeros_bits(h) >= difficulty:
            assert validate_pow(client_id, endpoint, body_hash, str(nonce), difficulty)
            break
        nonce += 1
