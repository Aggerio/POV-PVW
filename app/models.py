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


# --------------------
# V2 models (non-breaking additions)
# --------------------

class Ticket(BaseModel):
    client_id: str
    endpoint: str
    body_hash: str
    nonce: Union[str, int]
    difficulty: int


class Receipt(BaseModel):
    commitment: str
    txid: str
    ticket_hash: str
    timestamp: int


class IssueV2Request(BaseModel):
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    ticket: Ticket


class IssueV2Response(BaseModel):
    watermarked: str
    receipt: Receipt
    sig: str


class EvidenceV2(BaseModel):
    commitment: Optional[str] = None
    txid: Optional[str] = None


class VerifyV2Request(BaseModel):
    content: str
    client_id: str
    ticket: Optional[Ticket] = None
    evidence: Optional[EvidenceV2] = None
    pow: Optional[PoWTicket] = None


class DetectionResult(BaseModel):
    statistic: float
    pvalue: float
    present: bool


class VerifyV2Response(BaseModel):
    detection: DetectionResult
    transcript: Dict[str, Any]
    sig: str
    txid: str
