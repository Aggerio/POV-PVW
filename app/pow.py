from typing import Dict, Any
from .utils import sha256_hex, leading_zeros_bits, canonical_json

def validate_pow(client_id: str, endpoint: str, body_hash: str, nonce: str, difficulty: int)->bool:
    material = f"{client_id}|{endpoint}|{body_hash}|{nonce}".encode()
    h = sha256_hex(material)
    return leading_zeros_bits(h) >= difficulty


def serialize_ticket(ticket: Dict[str, Any]) -> bytes:
    """Canonical serialization of a PoW ticket for hashing and HKDF input.

    Expected keys: client_id, endpoint, body_hash, nonce, difficulty.
    """
    # Normalize fields to stable types
    normalized = {
        "client_id": str(ticket["client_id"]),
        "endpoint": str(ticket["endpoint"]),
        "body_hash": str(ticket["body_hash"]),
        "nonce": str(ticket["nonce"]),
        "difficulty": int(ticket["difficulty"]),
    }
    return canonical_json(normalized)


def ticket_hash_hex(ticket: Dict[str, Any]) -> str:
    """Compute SHA-256 hex hash of the canonicalized ticket."""
    return sha256_hex(serialize_ticket(ticket))


def validate_pow_ticket(ticket: Dict[str, Any]) -> bool:
    """Validate PoW from a ticket dict (compat with validate_pow())."""
    return validate_pow(
        str(ticket["client_id"]),
        str(ticket["endpoint"]),
        str(ticket["body_hash"]),
        str(ticket["nonce"]),
        int(ticket["difficulty"]),
    )
