import hashlib
from fastapi.testclient import TestClient
from app.main import app
from app.pow import serialize_ticket, ticket_hash_hex
from app.utils import hkdf_sha256


client = TestClient(app)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_ticket_hash_deterministic():
    t1 = {"client_id":"u","endpoint":"/issue","body_hash":"bh","nonce":"1","difficulty":10}
    t2 = {"endpoint":"/issue","difficulty":10,"nonce":"1","client_id":"u","body_hash":"bh"}
    assert serialize_ticket(t1) == serialize_ticket(t2)
    assert ticket_hash_hex(t1) == ticket_hash_hex(t2)


def test_hkdf_seed_consistency():
    # Deterministic HKDF for same ticket+salt
    salt = bytes.fromhex("11"*32)
    ticket = {"client_id":"alice","endpoint":"/issue","body_hash":"00"*32,"nonce":"42","difficulty":8}
    ser = serialize_ticket(ticket)
    ikm = hashlib.sha256(ser).digest()
    s1 = hkdf_sha256(ikm, salt=salt, info=b"pov-pvw-seed", length=32)
    s2 = hkdf_sha256(ikm, salt=salt, info=b"pov-pvw-seed", length=32)
    assert s1 == s2 and len(s1) == 32


def solve_pow(client_id: str, endpoint: str, body_hash: str, difficulty: int=8):
    # Tiny solver for tests
    nonce = 0
    while True:
        h = hashlib.sha256(f"{client_id}|{endpoint}|{body_hash}|{nonce}".encode()).hexdigest()
        # leading zero bits
        bits = bin(int(h,16))[2:].zfill(256)
        zeros = len(bits) - len(bits.lstrip('0'))
        if zeros >= difficulty:
            return str(nonce)
        nonce += 1


def test_issue_then_verify_v2_roundtrip():
    # Issue
    text = "hello variant A"
    issue_endpoint = "/issue"
    issue_body = {
        "text": text,
        "model_id": "demo",
        "client_id": "alice",
        "pow": {"body_hash": sha256_hex(text.encode()), "nonce": "0", "difficulty": 8},
    }
    issue_body["pow"]["nonce"] = solve_pow(issue_body["client_id"], issue_endpoint, issue_body["pow"]["body_hash"], issue_body["pow"]["difficulty"])
    r = client.post(issue_endpoint, json=issue_body)
    assert r.status_code == 200, r.text
    data = r.json()
    watermarked = data["watermarked"]

    # Verify via v2 with the issuance ticket (bound to pre-watermarked text)
    ticket = {
        "client_id": issue_body["client_id"],
        "endpoint": "/issue",
        "body_hash": issue_body["pow"]["body_hash"],
        "nonce": issue_body["pow"]["nonce"],
        "difficulty": issue_body["pow"]["difficulty"],
    }
    verify_body = {
        "content": watermarked,
        "client_id": "alice",
        "ticket": ticket,
        # omit pow to keep test fast
    }
    rv = client.post("/verify_v2", json=verify_body)
    assert rv.status_code == 200, rv.text
    v = rv.json()
    assert v["detection"]["present"] is True
    assert v["detection"]["statistic"] >= 1.0
