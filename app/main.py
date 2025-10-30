import hashlib
from fastapi import FastAPI, HTTPException
from .models import (
    IssueRequest, IssueResponse, VerifyRequest, VerifyResponse,
    IssueV2Request, IssueV2Response, Receipt,
    VerifyV2Request, VerifyV2Response, DetectionResult,
)
from .pow import validate_pow, serialize_ticket, ticket_hash_hex
from . import ledger
from .utils import sha256_hex, hmac_sign, now_ms, get_server_salt, hkdf_sha256
from .watermark.embed import embed_text, embed_with_key
from .watermark.detect import detect_text, detect_with_key

app = FastAPI(title="PoW-PVW (Local Demo)")

@app.get("/") 
def root():
    return {"ok": True, "name": "pow-pvw-demo", "endpoints": ["/issue", "/verify"]}

@app.post("/issue", response_model=IssueResponse)
def issue(req: IssueRequest):
    # Validate PoW
    body_hash = req.pow.body_hash
    if not validate_pow(req.client_id, "/issue", body_hash, req.pow.nonce, req.pow.difficulty):
        raise HTTPException(status_code=400, detail="Invalid PoW ticket")
    # Build canonical ticket and derive seed via HKDF
    ticket = {
        "client_id": req.client_id,
        "endpoint": "/issue",
        "body_hash": body_hash,
        "nonce": req.pow.nonce,
        "difficulty": req.pow.difficulty,
    }
    serialized = serialize_ticket(ticket)
    server_salt = get_server_salt()
    seed = hkdf_sha256(hashlib.sha256(serialized).digest(), salt=server_salt, info=b"pov-pvw-seed", length=32)
    # Embed deterministically from seed
    watermarked, _tag = embed_with_key(req.text, seed)
    # Compute commitment = H(seed || server_salt)
    commitment = sha256_hex(seed + server_salt)
    t_hash = ticket_hash_hex(ticket)
    # Build record and sign a receipt (no private info leaked)
    record = {
        "type": "issue",
        "ts": now_ms(),
        "client_id": req.client_id,
        "model_id": req.model_id,
        "commitment": commitment,
        "ticket_hash": t_hash,
        "output_hash": sha256_hex(watermarked.encode()),
        "policy_v": 1,
    }
    sig = hmac_sign(record)
    record["receipt_sig"] = sig
    txid = ledger.append_record(record)
    return IssueResponse(commitment=commitment, txid=txid, receipt_sig=sig, watermarked=watermarked)

@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    # Validate PoW
    body_hash = req.pow.body_hash
    if not validate_pow(req.client_id, "/verify", body_hash, req.pow.nonce, req.pow.difficulty):
        raise HTTPException(status_code=400, detail="Invalid PoW ticket")
    # Resolve commitment
    commitment = None
    if req.evidence.txid:
        rec = ledger.find_commitment_by_txid(req.evidence.txid)
        if not rec:
            raise HTTPException(status_code=404, detail="Unknown txid")
        commitment = rec["commitment"]
    elif req.evidence.commitment:
        commitment = req.evidence.commitment
    else:
        raise HTTPException(status_code=400, detail="Provide evidence.commitment or evidence.txid")
    # Detect (legacy): server_salt used as legacy secret parameter
    server_salt = get_server_salt()
    det = detect_text(req.content, commitment, server_salt)
    decision = det["statistic"] >= 1.0 and det["pvalue"] <= 0.05
    transcript = {
        "type": "verify",
        "ts": now_ms(),
        "client_id": req.client_id,
        "commitment": commitment,
        "content_hash": sha256_hex(req.content.encode()),
        "statistic": det["statistic"],
        "pvalue": det["pvalue"],
        "decision": decision,
        "policy_v": 1,
    }
    sig = hmac_sign(transcript)
    txid = ledger.append_record({**transcript, "transcript_sig": sig})
    return VerifyResponse(decision=decision, statistic=det["statistic"], pvalue=det["pvalue"], transcript_sig=sig, txid=txid)


@app.post("/issue_v2", response_model=IssueV2Response)
def issue_v2(req: IssueV2Request):
    # Validate PoW using the ticket (the ticket contains difficulty & nonce bound to content hash)
    t = req.ticket
    if not validate_pow(t.client_id, t.endpoint, t.body_hash, str(t.nonce), int(t.difficulty)):
        raise HTTPException(status_code=400, detail="Invalid PoW ticket")

    # Derive seed from canonical ticket via HKDF
    tdict = {
        "client_id": t.client_id,
        "endpoint": t.endpoint,
        "body_hash": t.body_hash,
        "nonce": t.nonce,
        "difficulty": t.difficulty,
    }
    serialized = serialize_ticket(tdict)
    server_salt = get_server_salt()
    seed = hkdf_sha256(hashlib.sha256(serialized).digest(), salt=server_salt, info=b"pov-pvw-seed", length=32)

    # Embed deterministically from seed
    watermarked, _tag = embed_with_key(req.content, seed)

    # Compute commitment and ticket hash
    commitment = sha256_hex(seed + server_salt)
    t_hash = ticket_hash_hex(tdict)

    # Append ledger issue record (sign the record as well)
    record = {
        "type": "issue",
        "ts": now_ms(),
        "client_id": t.client_id,
        "model_id": req.metadata.get("model_id", "demo"),
        "commitment": commitment,
        "ticket_hash": t_hash,
        "output_hash": sha256_hex(watermarked.encode()),
        "policy_v": 1,
    }
    rec_sig = hmac_sign(record)
    record["sig"] = rec_sig
    txid = ledger.append_record(record)

    # Build receipt and sign it
    receipt_obj = {
        "commitment": commitment,
        "txid": txid,
        "ticket_hash": t_hash,
        "timestamp": record["ts"],
    }
    sig = hmac_sign(receipt_obj)

    return IssueV2Response(
        watermarked=watermarked,
        receipt=Receipt(**receipt_obj),
        sig=sig,
    )


@app.post("/verify_v2", response_model=VerifyV2Response)
def verify_v2(req: VerifyV2Request):
    # Validate PoW if provided (recommended)
    if req.pow is not None:
        if not validate_pow(req.client_id, "/verify", req.pow.body_hash, req.pow.nonce, req.pow.difficulty):
            raise HTTPException(status_code=400, detail="Invalid PoW ticket")

    server_salt = get_server_salt()
    ticket_hash = None
    commitment = None

    if req.ticket is not None:
        tdict = {
            "client_id": req.ticket.client_id,
            "endpoint": req.ticket.endpoint,
            "body_hash": req.ticket.body_hash,
            "nonce": req.ticket.nonce,
            "difficulty": req.ticket.difficulty,
        }
        serialized = serialize_ticket(tdict)
        seed = hkdf_sha256(hashlib.sha256(serialized).digest(), salt=server_salt, info=b"pov-pvw-seed", length=32)
        det = detect_with_key(req.content, seed)
        commitment = sha256_hex(seed + server_salt)
        ticket_hash = ticket_hash_hex(tdict)
        decision = det["present"]
    elif req.evidence is not None and (req.evidence.txid or req.evidence.commitment):
        # Legacy-style verification without seed (weaker): use pattern presence
        if req.evidence.txid:
            rec = ledger.find_commitment_by_txid(req.evidence.txid)
            if not rec:
                raise HTTPException(status_code=404, detail="Unknown txid")
            commitment = rec["commitment"]
        else:
            commitment = req.evidence.commitment  # type: ignore[assignment]
        legacy = detect_text(req.content, commitment, server_salt)
        det = {"statistic": legacy["statistic"], "pvalue": legacy["pvalue"], "present": legacy["statistic"] >= 1.0 and legacy["pvalue"] <= 0.05}
        decision = det["present"]
    else:
        raise HTTPException(status_code=400, detail="Provide either 'ticket' or 'evidence' with 'commitment' or 'txid'")

    transcript = {
        "type": "verify",
        "ts": now_ms(),
        "client_id": req.client_id,
        "commitment": commitment,
        "content_hash": sha256_hex(req.content.encode()),
        "statistic": det["statistic"],
        "pvalue": det["pvalue"],
        "decision": decision,
        "policy_v": 1,
    }
    if ticket_hash:
        transcript["ticket_hash"] = ticket_hash

    sig = hmac_sign(transcript)
    txid = ledger.append_record({**transcript, "sig": sig})

    return VerifyV2Response(
        detection=DetectionResult(statistic=det["statistic"], pvalue=det["pvalue"], present=decision),
        transcript=transcript,
        sig=sig,
        txid=txid,
    )
