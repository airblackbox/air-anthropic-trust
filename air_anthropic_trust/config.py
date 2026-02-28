"""Configuration models for AIR Trust Layer."""

from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk levels for tool classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


RISK_ORDER = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 1,
    RiskLevel.NONE: 0,
}


class ConsentGateConfig(BaseModel):
    """Configuration for consent gating."""
    enabled: bool = True
    always_require: List[str] = Field(default_factory=list)
    never_require: List[str] = Field(default_factory=list)
    timeout_seconds: int = 30
    risk_threshold: RiskLevel = RiskLevel.MEDIUM


class AuditLedgerConfig(BaseModel):
    """Configuration for audit ledger."""
    enabled: bool = True
    local_path: str = "~/.air-trust/audit-ledger.json"
    forward_to_gateway: bool = False
    max_entries: int = 10000


class VaultConfig(BaseModel):
    """Configuration for data vault."""
    enabled: bool = True
    categories: List[str] = Field(
        default_factory=lambda: ["api_key", "credential", "pii"]
    )
    custom_patterns: dict = Field(default_factory=dict)
    forward_to_gateway: bool = False
    ttl_seconds: int = 86400


class InjectionDetectionConfig(BaseModel):
    """Configuration for injection detection."""
    enabled: bool = True
    sensitivity: str = "medium"  # low, medium, high
    block_threshold: float = 0.8
    log_detections: bool = True


class AirTrustConfig(BaseModel):
    """Main configuration for AIR Trust Layer."""
    consent_gate: ConsentGateConfig = Field(default_factory=ConsentGateConfig)
    audit_ledger: AuditLedgerConfig = Field(default_factory=AuditLedgerConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    injection_detection: InjectionDetectionConfig = Field(
        default_factory=InjectionDetectionConfig
    )
    gateway_url: Optional[str] = None
    gateway_key: Optional[str] = None

    class Config:
        """Pydantic config."""
        use_enum_values = False
