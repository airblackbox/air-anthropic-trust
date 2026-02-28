"""Tamper-proof audit ledger with HMAC-SHA256 chain."""

import json
import os
import uuid
import hmac
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from .config import AuditLedgerConfig, RiskLevel


class AuditEntry:
    """Single entry in audit ledger."""

    def __init__(
        self,
        action: str,
        tool_name: str,
        risk_level: RiskLevel,
        consent_required: bool,
        consent_granted: bool,
        data_tokenized: bool,
        injection_detected: bool,
        metadata: Dict = None,
        sequence: int = 0,
        prev_hash: str = None,
    ):
        """
        Args:
            action: Action performed (e.g., 'tool_call', 'injection_blocked')
            tool_name: Tool name
            risk_level: Risk level
            consent_required: Whether consent was required
            consent_granted: Whether consent was granted
            data_tokenized: Whether data was tokenized
            injection_detected: Whether injection was detected
            metadata: Additional context
            sequence: Entry sequence number
            prev_hash: Hash of previous entry
        """
        self.id = str(uuid.uuid4())
        self.sequence = sequence
        self.action = action
        self.tool_name = tool_name
        self.risk_level = risk_level
        self.consent_required = consent_required
        self.consent_granted = consent_granted
        self.data_tokenized = data_tokenized
        self.injection_detected = injection_detected
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow().isoformat()
        self.prev_hash = prev_hash
        self.hash = None
        self.signature = None

    def compute_hash(self) -> str:
        """Compute SHA256 hash of entry content."""
        content = {
            "id": self.id,
            "sequence": self.sequence,
            "action": self.action,
            "tool_name": self.tool_name,
            "risk_level": str(self.risk_level),
            "consent_required": self.consent_required,
            "consent_granted": self.consent_granted,
            "data_tokenized": self.data_tokenized,
            "injection_detected": self.injection_detected,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def sign(self, key: bytes) -> str:
        """Sign entry with HMAC-SHA256."""
        message = f"{self.sequence}|{self.id}|{self.hash}|{self.prev_hash}"
        sig = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        self.signature = sig
        return sig

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "sequence": self.sequence,
            "action": self.action,
            "tool_name": self.tool_name,
            "risk_level": str(self.risk_level),
            "consent_required": self.consent_required,
            "consent_granted": self.consent_granted,
            "data_tokenized": self.data_tokenized,
            "injection_detected": self.injection_detected,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "signature": self.signature,
            "metadata": self.metadata,
        }


class ChainVerification:
    """Result of chain verification."""

    def __init__(self, valid: bool = True, errors: List[str] = None):
        self.valid = valid
        self.errors = errors or []

    def to_dict(self) -> Dict:
        return {"valid": self.valid, "errors": self.errors}


class AuditLedger:
    """Tamper-proof audit ledger with HMAC-SHA256 chain."""

    CHAIN_KEY_SIZE = 32  # 256 bits

    def __init__(self, config: AuditLedgerConfig = None):
        """
        Args:
            config: AuditLedgerConfig instance
        """
        self.config = config or AuditLedgerConfig()
        self.entries: List[AuditEntry] = []
        self.chain_key = None
        self.sequence = 0

        if self.config.enabled:
            self._init_chain()

    def _init_chain(self):
        """Initialize or load chain key."""
        key_path = Path(self.config.local_path).parent / ".chain-key"
        
        if key_path.exists():
            with open(key_path, "rb") as f:
                self.chain_key = f.read()
        else:
            # Create new chain
            key_path.parent.mkdir(parents=True, exist_ok=True)
            self.chain_key = os.urandom(self.CHAIN_KEY_SIZE)
            key_path.write_bytes(self.chain_key)
            key_path.chmod(0o600)

    def append(
        self,
        action: str,
        tool_name: str,
        risk_level: RiskLevel,
        consent_required: bool = False,
        consent_granted: bool = False,
        data_tokenized: bool = False,
        injection_detected: bool = False,
        metadata: Dict = None,
    ) -> AuditEntry:
        """Append entry to ledger.

        Args:
            action: Action performed
            tool_name: Tool name
            risk_level: Risk level
            consent_required: Whether consent was required
            consent_granted: Whether consent was granted
            data_tokenized: Whether data was tokenized
            injection_detected: Whether injection was detected
            metadata: Additional context

        Returns:
            AuditEntry
        """
        if not self.config.enabled:
            return None

        prev_entry = self.entries[-1] if self.entries else None
        prev_hash = (
            "0" * 64 if not prev_entry else prev_entry.hash
        )

        entry = AuditEntry(
            action=action,
            tool_name=tool_name,
            risk_level=risk_level,
            consent_required=consent_required,
            consent_granted=consent_granted,
            data_tokenized=data_tokenized,
            injection_detected=injection_detected,
            metadata=metadata,
            sequence=self.sequence,
            prev_hash=prev_hash,
        )

        entry.hash = entry.compute_hash()
        entry.sign(self.chain_key)

        self.entries.append(entry)
        self.sequence += 1

        return entry

    def verify(self) -> ChainVerification:
        """Verify chain integrity.

        Returns:
            ChainVerification result
        """
        errors = []

        for i, entry in enumerate(self.entries):
            # Verify hash
            expected_hash = entry.compute_hash()
            if entry.hash != expected_hash:
                errors.append(
                    f"Entry {i}: Hash mismatch "
                    f"(got {entry.hash}, expected {expected_hash})"
                )

            # Verify signature
            expected_sig = entry.sign(self.chain_key)
            if entry.signature != expected_sig:
                errors.append(
                    f"Entry {i}: Signature mismatch "
                    f"(got {entry.signature}, expected {expected_sig})"
                )

            # Verify chain link
            if i > 0:
                if entry.prev_hash != self.entries[i - 1].hash:
                    errors.append(
                        f"Entry {i}: Chain broken "
                        f"(prev_hash mismatch)"
                    )

        return ChainVerification(
            valid=len(errors) == 0,
            errors=errors
        )

    def get_recent(self, n: int = 50) -> List[AuditEntry]:
        """Get recent entries.

        Args:
            n: Number of recent entries to return

        Returns:
            List of AuditEntry objects
        """
        return self.entries[-n:]

    def export(self) -> List[Dict[str, Any]]:
        """Export all entries as dictionaries.

        Returns:
            List of entry dictionaries
        """
        return [entry.to_dict() for entry in self.entries]

    def stats(self) -> Dict[str, Any]:
        """Get ledger statistics.

        Returns:
            Dictionary with stats
        """
        actions = {}
        tools = {}
        risk_levels = {}

        for entry in self.entries:
            actions[entry.action] = actions.get(entry.action, 0) + 1
            tools[entry.tool_name] = tools.get(entry.tool_name, 0) + 1
            risk = str(entry.risk_level)
            risk_levels[risk] = risk_levels.get(risk, 0) + 1

        return {
            "total_entries": len(self.entries),
            "by_action": actions,
            "by_tool": tools,
            "by_risk_level": risk_levels,
            "enabled": self.config.enabled,
        }
