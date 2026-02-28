"""Data vault for sensitive data tokenization."""

import re
import uuid
from typing import Dict, List, Optional, Tuple
from .config import VaultConfig


class DataVault:
    """Tokenizes and stores sensitive data patterns."""

    # Built-in regex patterns for common secrets
    DEFAULT_PATTERNS = {
        "openai_key": r"sk-[A-Za-z0-9_-]{48}",
        "anthropic_key": r"sk-ant-[A-Za-z0-9_-]{48}",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "github_token": r"gh[pousr]{1}_[A-Za-z0-9_]{36,255}",
        "stripe_key": r"sk_(?:live|test)_[0-9a-zA-Z]{24}",
        "bearer_token": r"Bearer [A-Za-z0-9_\-\.]+",
        "private_key": r"-----BEGIN RSA PRIVATE KEY-----",
        "connection_string": (
            r"(?:mongodb|postgres|mysql)://[^\s]+"
        ),
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        "ssn": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "generic_password": r"(?i)password\s*[:=]\s*[^\s]+",
        "generic_secret": r"(?i)secret\s*[:=]\s*[^\s]+",
        "generic_api_key": r"(?i)api[_-]?key\s*[:=]\s*[^\s]+",
    }

    TOKEN_PREFIX = "[AIR:vault:"
    TOKEN_SUFFIX = "]"

    def __init__(self, config: VaultConfig = None):
        """
        Args:
            config: VaultConfig instance
        """
        self.config = config or VaultConfig()
        self.vault: Dict[str, Tuple[str, str]] = {}  # token -> (category, value)
        
        # Compile patterns
        self.patterns = {}
        for name, pattern in self.DEFAULT_PATTERNS.items():
            self.patterns[name] = re.compile(pattern)
        
        # Add custom patterns
        if self.config.custom_patterns:
            for name, pattern in self.config.custom_patterns.items():
                self.patterns[name] = re.compile(pattern)

    def tokenize(self, text: str) -> Dict[str, any]:
        """Tokenize sensitive data in text.

        Args:
            text: Input text potentially containing sensitive data

        Returns:
            {
                "result": tokenized text,
                "tokenized": bool (whether any data was found),
                "count": int (number of items tokenized)
            }
        """
        if not self.config.enabled or not text:
            return {"result": text, "tokenized": False, "count": 0}

        result = text
        tokenized_count = 0

        for category, pattern in self.patterns.items():
            matches = pattern.finditer(text)
            for match in matches:
                token_id = str(uuid.uuid4())[:8]
                token = (
                    f"{self.TOKEN_PREFIX}{category}:{token_id}"
                    f"{self.TOKEN_SUFFIX}"
                )
                self.vault[token] = (category, match.group(0))
                result = result.replace(match.group(0), token, 1)
                tokenized_count += 1

        return {
            "result": result,
            "tokenized": tokenized_count > 0,
            "count": tokenized_count
        }

    def detokenize(self, text: str) -> str:
        """Restore tokenized data.

        Args:
            text: Text with tokens

        Returns:
            Text with tokens replaced by original values
        """
        if not text:
            return text

        result = text
        for token, (category, value) in self.vault.items():
            result = result.replace(token, value)

        return result

    def stats(self) -> Dict[str, any]:
        """Get vault statistics.

        Returns:
            Dictionary with vault stats
        """
        categories = {}
        for token, (category, value) in self.vault.items():
            categories[category] = categories.get(category, 0) + 1

        return {
            "total_tokens": len(self.vault),
            "by_category": categories,
            "enabled": self.config.enabled,
        }

    def cleanup(self) -> int:
        """Remove expired tokens.

        Returns:
            Number of tokens removed
        """
        # In a full implementation, track creation times and remove
        # entries older than config.ttl_seconds
        return 0
