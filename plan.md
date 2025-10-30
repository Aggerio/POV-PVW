# Implementation Plan — Variant A: PoW‑derived seed embedding

This plan adapts your current FastAPI demo into the Variant A design where the client’s PoW ticket deterministically derives the watermark seed. It’s tailored to the existing code in this repo and breaks the work into small, verifiable steps.

## TL;DR
- Derive seed from the validated PoW ticket via HKDF with a server salt.
- Use that seed as the watermark key in embed and detect.
- Store only a commitment (H(seed || server_salt)) and ticket_hash in the ledger.
- Return a signed receipt from /issue; allow /verify with ticket or commitment/txid.
- Keep signatures HMAC first; optionally upgrade to Ed25519 later.

## Current state (as of repo scan)
- FastAPI app with endpoints: `/issue`, `/verify` in `app/main.py`.
- PoW: present and enforced via `validate_pow(client_id, endpoint, body_hash, nonce, difficulty)` in `app/pow.py` with leading‑zero bits rule.
- Embedder: `app/watermark/embed.py` uses a random seed and the same secret as a salt; embeds a simple tag `[wm:<hex>]`.
- Detector: `app/watermark/detect.py` checks presence of `"[wm:"`; not keyed by seed.
- Signatures: HMAC using a single secret from `data/secret.key` (also used as “salt”).
- Ledger: JSONL in `data/log.jsonl`, `append_record()` computes `txid = sha256(json.dumps(record, sort_keys=True))`.
- Models: Pydantic models for requests/responses (`app/models.py`).

## Gaps vs Variant A
- Seed is not derived from the PoW ticket; it’s random per issue.
- Server conflates “salt” and HMAC key.
- Embedder doesn’t accept a seed/key; detector not keyed by seed.
- Ledger lacks `ticket_hash`; issue receipt is not a separate object.
- `/verify` cannot take a ticket to recompute the seed; only commitment/txid.
- No canonical JSON serialization utilities for ticket hashing.
- No HKDF for seed derivation.

## Design choices for this iteration
- Use HKDF‑SHA256 with a dedicated `SERVER_SALT` for seed derivation.
- Keep HMAC‑SHA256 for receipts/transcripts using a separate `SERVER_KEY`.
- Canonical serialization: JSON with `sort_keys=True`, UTF‑8 bytes, and no whitespace changes.
- Ticket hashing: `ticket_hash = sha256_hex(serialize(ticket))`.
- Commitment: `commitment = sha256_hex(seed + SERVER_SALT)` where `seed` is raw bytes.
- Difficulty default: start with 20 leading zero bits (tunable).
- Backward compatibility: return current fields but add new receipt object; accept old request shapes during transition.

## API contracts (target)
- POST `/issue`
  - Request: `{ content: string, metadata?: object, ticket: { client_id, endpoint, body_hash, nonce, difficulty } }`
    - For compatibility with the current code, we also accept `{ text, model_id, client_id, pow: { body_hash, nonce, difficulty } }` in a transitional period.
  - Response:
    ```json
    {
      "watermarked": "string",
      "receipt": {
        "commitment": "hex",
        "txid": "hex",
        "ticket_hash": "hex",
        "timestamp": 1730332800000
      },
      "sig": "hex"
    }
    ```

- POST `/verify`
  - Request options:
    - With ticket: `{ content: string, ticket: {...}, client_id: string }`
    - With commitment/txid: `{ content: string, evidence: { commitment?: "hex", txid?: "hex" }, client_id: string }`
  - Response:
    ```json
    {
      "detection": { "statistic": 0.9, "pvalue": 0.01, "present": true },
      "transcript": { ... },
      "sig": "hex",
      "txid": "hex"
    }
    ```

## Data and crypto
- Ticket: `{ client_id, endpoint, body_hash, nonce, difficulty }`
- PoW check: `leading_zero_bits(sha256_hex(client_id|endpoint|body_hash|nonce)) >= difficulty`
- Seed derivation: `seed = HKDF(SHA256(serialize(ticket)), salt=SERVER_SALT, info="pov-pvw-seed", len=32)`
- Commitment: `H(seed || SERVER_SALT)` (hex string)
- Ledger: JSONL with `issue` and `verify` records; store `ticket_hash` and `commitment`; do not store seed or raw ticket unless explicitly enabled.

## Secrets, config, and environment
- `SERVER_SALT` (bytes): salt for HKDF and commitment; store separately from HMAC key.
- `SERVER_KEY` (bytes): HMAC signing key for receipts/transcripts.
- `LEDGER_PATH` (string): defaults to `data/log.jsonl`.
- `DEFAULT_DIFFICULTY` (int): default PoW difficulty (e.g., 20).
- Source secrets from env vars; if missing, fall back to files:
  - `data/server_salt.bin`, `data/hmac.key` (auto‑created if not present).

## Step‑by‑step implementation (by file)
Each step has an acceptance check. We’ll implement in this order.

1) utils: canonicalization, secrets, HKDF
- File: `app/utils.py`
- Add:
  - `canonical_json(obj) -> bytes` using `json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()`
  - `sha256_hex_bytes(b: bytes) -> str`
  - `hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes` (via cryptography)
  - Secret mgmt:
    - `get_server_salt() -> bytes` (env `SERVER_SALT` hex/base64 or file `data/server_salt.bin`)
    - `get_server_key() -> bytes` (env `SERVER_KEY` hex/base64 or file `data/hmac.key`)
  - `hmac_sign_bytes(key: bytes, payload_bytes: bytes) -> str` and keep `hmac_sign(obj)` wrapper.
- Keep existing helpers (`sha256_hex`, `leading_zeros_bits`, `now_ms`) but refactor to reuse canonical_json and separated secrets.
- Acceptance: unit tests can import and call hkdf and secrets without side effects; both secrets are distinct.

2) pow: ticket helpers and validation
- File: `app/pow.py`
- Add serialization helper:
  - `serialize_ticket(ticket: dict) -> bytes` (canonical JSON); alt path: build f"{client_id}|{endpoint}|{body_hash}|{nonce}" bytes (keep existing for compatibility) but prefer JSON for hashing.
- Expose `validate_pow_ticket(ticket: dict) -> bool` alongside the existing `validate_pow(...)`.
- Acceptance: both forms validate identically for equivalent data; keep current tests green.

3) models: new schemas (non‑breaking)
- File: `app/models.py`
- Add new Pydantic models in parallel to existing ones:
  - `Ticket` with fields `{ client_id: str, endpoint: str, body_hash: str, nonce: Union[str,int], difficulty: int }`
  - `IssueV2Request` with `{ content: str, metadata: Dict[str, Any], ticket: Ticket }`
  - `IssueV2Response` with `{ watermarked: str, receipt: {...}, sig: str }`
  - `VerifyV2Request` with `{ content: str, ticket?: Ticket, evidence?: {commitment?, txid?}, client_id: str }`
  - `VerifyV2Response` with `{ detection: {...}, transcript: {...}, sig: str, txid: str }`
- Keep existing v1 models for a transitional path; annotate deprecation.
- Acceptance: FastAPI starts with both schemas importable.

4) seed derivation module
- New (or place in utils): `derive_seed_from_ticket(serialized_ticket: bytes, server_salt: bytes) -> bytes` using HKDF‑SHA256.
- Acceptance: deterministic equality for repeated invocations; length 32 bytes.

5) embedder: accept seed
- File: `app/watermark/embed.py`
- Change `embed_text(text, server_salt)` to `embed_text(text, key: bytes) -> (watermarked, tag_hex)` or keep returning `(watermarked, commitment, seed_hex)` for demo but compute deterministically from `key`.
- Recommended minimal demo behavior:
  - `tag = sha256_hex(key)[:16]`, append `ZWSP + [wm:<tag>]` to text.
  - Commitment calculation will move to caller.
- Acceptance: calling with same key yields identical output/tag.

6) detector: accept seed and/or commitment
- File: `app/watermark/detect.py`
- Update to:
  - `detect_text(content: str, key: bytes) -> {statistic, pvalue, present}` by recomputing expected tag from key and scanning.
  - Optionally support `detect_text_with_commitment(content, commitment, server_salt, key)` to cross‑check commitment in transcripts.
- Acceptance: returns present=true for content produced by new embedder given same key; false otherwise.

7) ledger: add `ticket_hash`, signatures in records
- File: `app/ledger.py`
- Extend `append_record(record) -> txid` (keep) and add helpers:
  - `append_issue(record_with_sig)`, `append_verify(record_with_sig)` (thin wrappers, optional)
  - Ensure `txid` is computed on the record without `txid` field itself (current code already OK as it hashes the record before adding txid in file line context).
- Records include:
  - issue: `{ type, ts, client_id, model_id|metadata, commitment, ticket_hash, output_hash, policy_v, sig }`
  - verify: `{ type, ts, client_id, commitment, content_hash, statistic, pvalue, decision, policy_v, sig }`
- Acceptance: `find_commitment_by_txid()` continues to work; new fields visible in the JSONL.

8) main: wire /issue and /verify v2 flows
- File: `app/main.py`
- `/issue` changes:
  - Accept either v1 (`IssueRequest`) or v2 (`IssueV2Request`) payloads. Normalize into a `ticket` dict.
  - Validate PoW using `validate_pow`/`validate_pow_ticket`.
  - `serialized_ticket = canonical_json(ticket)`; compute `ticket_hash`.
  - `seed = hkdf_sha256(sha256(serialized_ticket), salt=SERVER_SALT, info=b"pov-pvw-seed", length=32)`.
  - `watermarked = embed_text(content, key=seed)`.
  - `commitment = sha256_hex(seed + SERVER_SALT)`.
  - Build `issue_record` with `ticket_hash` and `commitment`; sign `receipt = {commitment, txid, ticket_hash, timestamp}` with HMAC over `canonical_json(receipt)`.
  - Append to ledger; return `{ watermarked, receipt, sig }`. Optionally also keep existing `{commitment, txid, receipt_sig}` for backward compatibility.
- `/verify` changes:
  - Accept either `ticket` or `evidence.{commitment|txid}`. If `ticket` provided, recompute `seed` and run `detect_text(content, key=seed)` directly. If only `commitment/txid`, resolve commitment, but seed‑less detection (for demo) will still scan for tag computed from recomputed seed, hence must have the ticket; document that supplying ticket is preferred.
  - Build and sign transcript; append to ledger; return detection + transcript.
- Acceptance: manual end‑to‑end works with new contract and legacy contract.

9) requirements
- File: `requirements.txt`
- Add: `cryptography>=42` (HKDF). Keep pinned versions consistent.
- Acceptance: app installs and starts.

10) tests
- New tests to add under `tests/`:
  1. `test_validate_pow_valid_ticket` — fixed, precomputed ticket validates.
  2. `test_derive_seed_consistency` — identical seeds for repeated calls.
  3. `test_commitment_non_recovery` — commitment differs from seed and does not allow recovering seed (basic property check).
  4. `test_issue_verify_roundtrip` — solve small‑difficulty ticket, call `/issue`, then `/verify` with same ticket and content.
- Keep existing `test_pow.py`; add a new module `test_variant_a.py`.
- Acceptance: all tests green locally.

## Records format (JSONL)
- issue:
  ```json
  {
    "type": "issue",
    "ts": 1730332800000,
    "client_id": "...",
    "commitment": "hex",
    "ticket_hash": "hex",
    "output_hash": "hex",
    "policy_v": 1,
    "sig": "hex"
  }
  ```
- verify:
  ```json
  {
    "type": "verify",
    "ts": 1730332805000,
    "client_id": "...",
    "commitment": "hex",
    "content_hash": "hex",
    "statistic": 1.0,
    "pvalue": 0.01,
    "decision": true,
    "policy_v": 1,
    "sig": "hex"
  }
  ```

## Migration & compatibility
- Keep existing `IssueRequest`/`IssueResponse` and `/verify` payloads working during transition.
- Prefer v2 shapes (`ticket`, `receipt`) in docs; deprecate v1 fields in a later pass.

## Security notes and future work
- Separate `SERVER_SALT` and `SERVER_KEY`; rotate keys with versioned headers if needed.
- For public verifiability without trusting server, migrate HMAC → Ed25519 (future step).
- Optionally store `ticket` in ledger behind a privacy flag; default to storing only `ticket_hash`.

## Rollout plan
1. Land utils + seed derivation + requirements (no endpoint changes yet).
2. Update embed/detect to be seed‑aware behind a feature flag.
3. Add new models and v2 endpoint handlers; keep v1 paths functional.
4. Extend ledger to include `ticket_hash`.
5. Turn on v2 response content; update README examples.
6. Add tests and CI hooks.

## Acceptance criteria (green gates)
- Build: PASS — app installs with updated requirements.
- Lint/Type: PASS — mypy/pylance clean for changed files (best‑effort in this demo).
- Tests: PASS — new and existing tests green.
- Manual: `/issue` and `/verify` work with both legacy and new payloads; ledger shows `ticket_hash` and `commitment`.

## Estimates
- Server changes (v2 paths + utils + embed/detect): ~4–6 hours.
- Tests and docs updates: ~2–3 hours.
- Optional Ed25519 integration: ~2 hours extra.

---

When you approve, I’ll start with Step 1 (utils + HKDF + secrets separation), then proceed in the order above, validating each step with quick tests and keeping backward compatibility intact.
