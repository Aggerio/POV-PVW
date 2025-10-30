import hashlib
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def leading_zero_bits(hexh: str) -> int:
    bits = bin(int(hexh, 16))[2:].zfill(256)
    return len(bits) - len(bits.lstrip('0'))


def solve_pow(client_id: str, endpoint: str, body_hash: str, difficulty: int=8):
    nonce = 0
    while True:
        h = hashlib.sha256(f"{client_id}|{endpoint}|{body_hash}|{nonce}".encode()).hexdigest()
        if leading_zero_bits(h) >= difficulty:
            return str(nonce)
        nonce += 1


def test_issue_v2_receipt_shape():
    content = "doc"
    client_id = "bob"
    endpoint = "/issue"
    difficulty = 8
    bh = sha256_hex(content.encode())
    nonce = solve_pow(client_id, endpoint, bh, difficulty)

    payload = {
        "content": content,
        "metadata": {"model_id": "demo"},
        "ticket": {
            "client_id": client_id,
            "endpoint": endpoint,
            "body_hash": bh,
            "nonce": nonce,
            "difficulty": difficulty,
        }
    }
    r = client.post("/issue_v2", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "watermarked" in data
    assert "receipt" in data and "sig" in data
    rc = data["receipt"]
    for k in ("commitment", "txid", "ticket_hash", "timestamp"):
        assert k in rc
