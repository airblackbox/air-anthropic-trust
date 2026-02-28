"""Consent gating for tool execution."""

from typing import Optional, Dict, Any
from .config import ConsentGateConfig, RiskLevel, RISK_ORDER


class ConsentGate:
    """Manages consent requirements for tool execution."""

    # Risk classification for common tools
    TOOL_RISK_MAP = {
        # CRITICAL: execution/spawning
        "exec": RiskLevel.CRITICAL,
        "spawn": RiskLevel.CRITICAL,
        "shell": RiskLevel.CRITICAL,
        "system": RiskLevel.CRITICAL,
        "eval": RiskLevel.CRITICAL,
        # HIGH: filesystem modifications
        "fs_write": RiskLevel.HIGH,
        "write_file": RiskLevel.HIGH,
        "delete": RiskLevel.HIGH,
        "remove_file": RiskLevel.HIGH,
        "rm": RiskLevel.HIGH,
        "deploy": RiskLevel.HIGH,
        "create_file": RiskLevel.HIGH,
        # MEDIUM: network/communication
        "send_email": RiskLevel.MEDIUM,
        "http_request": RiskLevel.MEDIUM,
        "post": RiskLevel.MEDIUM,
        "api_call": RiskLevel.MEDIUM,
        "slack_send": RiskLevel.MEDIUM,
        # LOW: read operations
        "fs_read": RiskLevel.LOW,
        "read_file": RiskLevel.LOW,
        "search": RiskLevel.LOW,
        "list_files": RiskLevel.LOW,
    }

    def __init__(self, config: ConsentGateConfig = None):
        """
        Args:
            config: ConsentGateConfig instance
        """
        self.config = config or ConsentGateConfig()

    def classify_risk(self, tool_name: str) -> RiskLevel:
        """Classify risk level of a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            RiskLevel classification
        """
        # Direct match
        if tool_name in self.TOOL_RISK_MAP:
            return self.TOOL_RISK_MAP[tool_name]

        # Fuzzy match (substring)
        tool_lower = tool_name.lower()
        for pattern, level in self.TOOL_RISK_MAP.items():
            if pattern in tool_lower or tool_lower in pattern:
                return level

        # Default to MEDIUM
        return RiskLevel.MEDIUM

    def requires_consent(self, tool_name: str) -> bool:
        """Check if tool requires consent.

        Args:
            tool_name: Name of the tool

        Returns:
            True if consent is required
        """
        if not self.config.enabled:
            return False

        # Check explicit lists
        if tool_name in self.config.always_require:
            return True
        if tool_name in self.config.never_require:
            return False

        # Check against risk threshold
        risk = self.classify_risk(tool_name)
        threshold_order = RISK_ORDER[self.config.risk_threshold]
        tool_order = RISK_ORDER[risk]

        return tool_order >= threshold_order

    def intercept(
        self,
        tool_name: str,
        tool_args: Dict[str, Any] = None,
        prompt_fn=None
    ) -> Dict[str, Any]:
        """Intercept tool execution for consent check.

        Args:
            tool_name: Name of the tool
            tool_args: Tool arguments
            prompt_fn: Optional function to prompt for consent

        Returns:
            {"blocked": bool, "reason": str|None}
        """
        if not self.config.enabled:
            return {"blocked": False, "reason": None}

        if not self.requires_consent(tool_name):
            return {"blocked": False, "reason": None}

        risk = self.classify_risk(tool_name)
        reason = (
            f"Tool '{tool_name}' requires consent "
            f"(risk: {risk})"
        )

        if prompt_fn:
            try:
                approved = prompt_fn(tool_name, risk, tool_args)
                if not approved:
                    return {
                        "blocked": True,
                        "reason": f"Consent denied by user: {reason}"
                    }
            except Exception as e:
                return {
                    "blocked": True,
                    "reason": f"Consent check failed: {str(e)}"
                }

        return {"blocked": False, "reason": None}

    def format_consent_message(
        self,
        tool_name: str,
        tool_args: Dict[str, Any] = None
    ) -> str:
        """Format a human-readable consent request.

        Args:
            tool_name: Name of the tool
            tool_args: Tool arguments

        Returns:
            Formatted consent message
        """
        risk = self.classify_risk(tool_name)
        message = (
            f"Request consent for tool execution:\n"
            f"  Tool: {tool_name}\n"
            f"  Risk: {risk}\n"
        )

        if tool_args:
            message += f"  Args: {tool_args}\n"

        message += f"\nAllow execution? (y/n): "
        return message
