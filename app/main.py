from fastapi import FastAPI, HTTPException
from .models import IssueRequest, IssueResponse, VerifyRequest, VerifyResponse
from .pow import validate_pow
from . import ledger
from .utils import sha256_hex, hmac_sign, ensure_secret, now_ms
from .watermark.embed import embed_text
from .watermark.detect import detect_text

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
    # Embed watermark
    secret = ensure_secret()
    watermarked, commitment, seed_hex = embed_text(req.text, secret)
    # Build record and sign a receipt (no private info leaked)
    record = {
        "type": "issue",
        "ts": now_ms(),
        "client_id": req.client_id,
        "model_id": req.model_id,
        "commitment": commitment,
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
    # Detect
    secret = ensure_secret()
    det = detect_text(req.content, commitment, secret)
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
