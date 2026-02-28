"""AIR Trust Layer error classes."""


class AirTrustError(Exception):
    """Base exception for AIR Trust Layer."""

    def __init__(self, message: str, details: dict = None):
        """
        Args:
            message: Error message
            details: Additional error context
        """
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def __str__(self):
        if self.details:
            return f"{self.message} | {self.details}"
        return self.message


class ConsentDeniedError(AirTrustError):
    """Raised when consent gate denies tool execution."""

    def __init__(self, tool_name: str, risk_level: str, reason: str = None):
        """
        Args:
            tool_name: Name of the tool that was blocked
            risk_level: Risk level of the tool
            reason: Optional reason for denial
        """
        self.tool_name = tool_name
        self.risk_level = risk_level
        message = (
            f"Consent denied for tool '{tool_name}' "
            f"(risk: {risk_level})"
        )
        if reason:
            message += f": {reason}"
        super().__init__(
            message,
            {"tool_name": tool_name, "risk_level": risk_level}
        )


class InjectionBlockedError(AirTrustError):
    """Raised when injection detection blocks input."""

    def __init__(self, score: float, patterns: list = None):
        """
        Args:
            score: Injection detection confidence score
            patterns: List of detected injection patterns
        """
        self.score = score
        self.patterns = patterns or []
        message = (
            f"Prompt injection detected (score: {score:.2f})"
        )
        super().__init__(
            message,
            {"score": score, "patterns": patterns}
        )
