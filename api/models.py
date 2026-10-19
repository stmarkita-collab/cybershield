"""Pydantic models untuk API."""
from pydantic import BaseModel, Field
from typing import Optional, List


class PasswordRequest(BaseModel):
    password: str
    check_hibp: bool = False


class PhishingRequest(BaseModel):
    url: str
    fast: bool = False  # skip network checks


class PortScanRequest(BaseModel):
    target: str
    preset: str = "top100"
    ports: Optional[str] = None  # e.g. "22,80,443" or "1-1000"
    workers: int = Field(default=100, ge=1, le=500)
    timeout: float = Field(default=1.0, ge=0.1, le=10.0)


class DNSRequest(BaseModel):
    domain: str


class WebAuditRequest(BaseModel):
    url: str
    ignore_ssl: bool = False


class SSLRequest(BaseModel):
    host: str
    port: int = 443


class SubdomainRequest(BaseModel):
    domain: str
    use_crtsh: bool = True


class DirectoryRequest(BaseModel):
    url: str
    ignore_ssl: bool = False
    recursive: bool = False


class TechRequest(BaseModel):
    url: str
    ignore_ssl: bool = False


class VulnRequest(BaseModel):
    url: str
    ignore_ssl: bool = False


class EmailRequest(BaseModel):
    domain: str


class APIResponse(BaseModel):
    success: bool
    data: Optional[dict] = None
    error: Optional[str] = None
