import os, json, hashlib, time
from typing import Dict, Any, Optional

LEDGER_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "log.jsonl")
os.makedirs(os.path.dirname(LEDGER_PATH), exist_ok=True)

def append_record(record: Dict[str, Any])->str:
    data = json.dumps(record, sort_keys=True).encode()
    txid = hashlib.sha256(data).hexdigest()
    line = json.dumps({"txid": txid, **record}, ensure_ascii=False)
    with open(LEDGER_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return txid

def find_commitment_by_txid(txid: str)->Optional[Dict[str, Any]]:
    if not os.path.exists(LEDGER_PATH):
        return None
    with open(LEDGER_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                if obj.get("txid") == txid and obj.get("type") == "issue":
                    return obj
            except Exception:
                continue
    return None
