import hashlib, json
from fastapi.testclient import TestClient
from app.main import app
from app.pow import validate_pow

client = TestClient(app)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def leading_zero_bits(hexh: str) -> int:
    bits = bin(int(hexh, 16))[2:].zfill(256)
    return len(bits) - len(bits.lstrip('0'))

def solve_pow(client_id: str, endpoint: str, body_hash: str, difficulty: int=8) -> str:
    nonce = 0
    while True:
        h = hashlib.sha256(f"{client_id}|{endpoint}|{body_hash}|{nonce}".encode()).hexdigest()
        if leading_zero_bits(h) >= difficulty:
            return str(nonce)
        nonce += 1

def main():
    text = 'Hello Variant A — demo run'
    client_id = 'alice'
    endpoint = '/issue'
    body_hash = sha256_hex(text.encode())
    difficulty = 8
    nonce = solve_pow(client_id, endpoint, body_hash, difficulty)
    assert validate_pow(client_id, endpoint, body_hash, nonce, difficulty)

    issue_payload = {
        'content': text,
        'metadata': {'model_id': 'demo'},
        'ticket': {
            'client_id': client_id,
            'endpoint': endpoint,
            'body_hash': body_hash,
            'nonce': nonce,
            'difficulty': difficulty,
        }
    }
    issue_resp = client.post('/issue_v2', json=issue_payload)
    print('ISSUE_V2 status:', issue_resp.status_code)
    data = issue_resp.json()
    print('ISSUE_V2 json:', json.dumps(data, indent=2))
    wm = data['watermarked']

    verify_payload = {
        'content': wm,
        'client_id': client_id,
        'ticket': issue_payload['ticket'],
    }
    verify_resp = client.post('/verify_v2', json=verify_payload)
    print('VERIFY_V2 status:', verify_resp.status_code)
    print('VERIFY_V2 json:', json.dumps(verify_resp.json(), indent=2))

if __name__ == '__main__':
    main()
