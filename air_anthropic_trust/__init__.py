"""AIR Trust Layer for Anthropic Claude Agent SDK.

Provides audit trails, data tokenization, consent gates, and injection
detection for EU AI Act compliance.
"""

from .config import (
    AirTrustConfig,
    RiskLevel,
    RISK_ORDER,
    ConsentGateConfig,
    AuditLedgerConfig,
    VaultConfig,
    InjectionDetectionConfig,
)
from .errors import AirTrustError, ConsentDeniedError, InjectionBlockedError
from .hooks import AirTrustHooks

__version__ = "0.1.0"
__author__ = "AIR Blackbox"
__license__ = "MIT"

__all__ = [
    "AirTrustHooks",
    "AirTrustConfig",
    "AirTrustError",
    "ConsentDeniedError",
    "InjectionBlockedError",
    "RiskLevel",
    "RISK_ORDER",
    "ConsentGateConfig",
    "AuditLedgerConfig",
    "VaultConfig",
    "InjectionDetectionConfig",
]
