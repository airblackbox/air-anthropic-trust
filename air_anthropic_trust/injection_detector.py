"""Prompt injection detection with weighted patterns."""

import re
from typing import Dict, List, Tuple
from .config import InjectionDetectionConfig


class InjectionResult:
    """Result of injection detection scan."""

    def __init__(
        self,
        detected: bool,
        score: float,
        patterns: List[Tuple[str, float]] = None,
        blocked: bool = False,
    ):
        """
        Args:
            detected: Whether injection was detected
            score: Confidence score (0.0-1.0)
            patterns: List of (pattern_name, weight) tuples matched
            blocked: Whether execution was blocked
        """
        self.detected = detected
        self.score = score
        self.patterns = patterns or []
        self.blocked = blocked

    def to_dict(self):
        return {
            "detected": self.detected,
            "score": self.score,
            "patterns": [{"name": p[0], "weight": p[1]} for p in self.patterns],
            "blocked": self.blocked,
        }


class InjectionDetector:
    """Detects prompt injection attacks."""

    # Weighted injection patterns
    PATTERNS = {
        # Role override attacks (weight: 0.9)
        "role_override": (
            r"(?i)(ignore|forget|disregard).*(?:instructions|rules|guidelines)",
            0.9,
        ),
        # System prompt override (weight: 0.95)
        "system_prompt": (
            r"(?i)(system prompt|system instructions|system message).*[:=]",
            0.95,
        ),
        # Delimiter injection (weight: 0.8)
        "delimiter": (
            r"(?i)(---|\[END\]|===|###).*(?:instructions|prompt|rules)",
            0.8,
        ),
        # XML tag injection (weight: 0.85)
        "xml_tags": (
            r"<(instruction|system|admin|command)[^>]*>",
            0.85,
        ),
        # Privilege escalation (weight: 0.9)
        "privilege_escalation": (
            r"(?i)(admin|root|superuser|sudo).*(?:mode|access|rights)",
            0.9,
        ),
        # Safety bypass (weight: 0.95)
        "safety_bypass": (
            r"(?i)(bypass|override|disable|ignore).*(?:safety|filter|restrictions)",
            0.95,
        ),
        # Output manipulation (weight: 0.7)
        "output_manipulation": (
            r"(?i)(output|return|respond).*(?:only|exactly|precisely)",
            0.7,
        ),
        # Encoding evasion (weight: 0.75)
        "encoding_evasion": (
            r"(?i)(base64|hex|encoded|encrypt).*(?:decode|interpret)",
            0.75,
        ),
        # Hidden instructions (weight: 0.8)
        "hidden_instructions": (
            r"(?i)(hidden|secret|covert|private).*(?:instruction|command|message)",
            0.8,
        ),
        # Urgent override (weight: 0.7)
        "urgent_override": (
            r"(?i)(urgent|critical|emergency|immediately).*(?:ignore|bypass|override)",
            0.7,
        ),
        # Tool abuse (weight: 0.85)
        "tool_abuse": (
            r"(?i)(use|call|invoke).*(?:execute|run|perform).*(?:dangerous|harmful|malicious)",
            0.85,
        ),
        # Data exfiltration (weight: 0.9)
        "data_exfiltration": (
            r"(?i)(extract|steal|leak|exfiltrate).*(?:data|information|secrets)",
            0.9,
        ),
        # DAN jailbreak (weight: 0.9)
        "dan_jailbreak": (
            r"(?i)(do anything now|DAN|jailbreak|unrestricted)",
            0.9,
        ),
        # Hypothetical bypass (weight: 0.75)
        "hypothetical_bypass": (
            r"(?i)(hypothetical|suppose|imagine|pretend).*(?:could|would|can).*(?:bypass|ignore)",
            0.75,
        ),
        # Token smuggling (weight: 0.8)
        "token_smuggling": (
            r"(?i)(token|credential|secret|key|password).*(?:smuggle|hide|embed)",
            0.8,
        ),
    }

    def __init__(self, config: InjectionDetectionConfig = None):
        """
        Args:
            config: InjectionDetectionConfig instance
        """
        self.config = config or InjectionDetectionConfig()
        self.compiled_patterns = {}

        # Compile patterns
        for name, (pattern, weight) in self.PATTERNS.items():
            self.compiled_patterns[name] = (
                re.compile(pattern),
                weight,
            )

    def scan(self, content: str) -> InjectionResult:
        """Scan content for injection patterns.

        Args:
            content: Text to scan

        Returns:
            InjectionResult
        """
        if not self.config.enabled or not content:
            return InjectionResult(
                detected=False,
                score=0.0,
                patterns=[],
                blocked=False,
            )

        matched_patterns = []
        total_weight = 0.0

        # Select patterns based on sensitivity
        patterns_to_check = self.compiled_patterns.items()
        if self.config.sensitivity == "low":
            # Only check high-confidence patterns
            patterns_to_check = [
                (n, (p, w)) for n, (p, w) in patterns_to_check
                if w >= 0.85
            ]
        elif self.config.sensitivity == "high":
            # More aggressive thresholds
            pass  # Use all patterns

        # Scan
        for name, (pattern, weight) in patterns_to_check:
            if pattern.search(content):
                matched_patterns.append((name, weight))
                total_weight += weight

        # Calculate score (normalized)
        max_possible = sum(w for _, w in self.PATTERNS.values())
        score = total_weight / max_possible if max_possible > 0 else 0.0
        score = min(score, 1.0)  # Cap at 1.0

        detected = len(matched_patterns) > 0
        blocked = (
            detected and score >= self.config.block_threshold
        )

        if detected and self.config.log_detections:
            # In production, log to audit system
            pass

        return InjectionResult(
            detected=detected,
            score=score,
            patterns=matched_patterns,
            blocked=blocked,
        )
