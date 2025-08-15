from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, Union

class PoWTicket(BaseModel):
    body_hash: str
    nonce: str
    difficulty: int

class IssueRequest(BaseModel):
    text: str
    model_id: str = "demo"
    client_id: str
    params: Dict[str, Any] = Field(default_factory=dict)
    pow: PoWTicket

class IssueResponse(BaseModel):
    commitment: str
    txid: str
    receipt_sig: str
    watermarked: str

class Evidence(BaseModel):
    commitment: Optional[str] = None
    txid: Optional[str] = None

class VerifyRequest(BaseModel):
    content: str
    evidence: Evidence
    client_id: str
    pow: PoWTicket

class VerifyResponse(BaseModel):
    decision: bool
    statistic: float
    pvalue: float
    transcript_sig: str
    txid: str
