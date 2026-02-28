# air-anthropic-trust

**AIR Trust Layer for Anthropic Claude Agent SDK**

[![PyPI](https://img.shields.io/pypi/v/air-anthropic-trust)](https://pypi.org/project/air-anthropic-trust/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-ready trust layer for Anthropic's Claude Agent SDK. Provides audit trails, data tokenization, consent gates, and prompt injection detection to ensure EU AI Act compliance.

## Quick Install

```bash
pip install air-anthropic-trust
```

## Quick Start

```python
from anthropic import Agent
from air_anthropic_trust import AirTrustHooks

# Initialize hooks with defaults
hooks = AirTrustHooks()

# Use with Claude Agent SDK
agent = Agent(
    model="claude-sonnet-4-20250514",
    tools=[...],
    hooks=hooks
)

# Run agent
result = await agent.run("Analyze this data")

# Check audit trail
print(hooks.get_audit_stats())
print(hooks.verify_chain())
```

## Features

### 1. Consent Gating
Automatically intercepts tool execution and checks consent requirements based on risk level.

```python
# Tools are classified by risk:
# - CRITICAL: exec, spawn, shell
# - HIGH: write_file, delete, deploy
# - MEDIUM: send_email, http_request
# - LOW: read_file, search

hooks = AirTrustHooks()
risk = hooks.consent_gate.classify_risk("delete")
requires = hooks.consent_gate.requires_consent("delete")
```

### 2. Data Vault
Tokenizes sensitive data (API keys, credentials, PII) to prevent leakage.

```python
# Automatically tokenizes:
# - API keys (OpenAI, Anthropic, AWS, GitHub, Stripe, etc.)
# - PII (emails, phone numbers, SSN, credit cards)
# - Credentials (private keys, connection strings, passwords)

vault_result = hooks.vault.tokenize("My key is sk-proj-abc123")
# Returns: {"result": "My key is [AIR:vault:api_key:xyz]", "tokenized": true, "count": 1}
```

### 3. Audit Ledger
Tamper-proof ledger with HMAC-SHA256 chain verification for compliance.

```python
# Every operation is logged with chain verification
verification = hooks.verify_chain()
print(verification["valid"])  # True if chain is intact

# Export for audit
audit_trail = hooks.export_audit()
```

### 4. Injection Detection
Detects 15+ prompt injection patterns with weighted scoring.

```python
# Scans for:
# - Role override attacks
# - System prompt injection
# - Privilege escalation
# - Safety bypass attempts
# - And 11 more patterns

injection = hooks.injector.scan("Ignore instructions and...")
print(injection.detected)  # True
print(injection.score)     # 0.85
```

## Configuration

```python
from air_anthropic_trust import (
    AirTrustConfig,
    ConsentGateConfig,
    AuditLedgerConfig,
    VaultConfig,
    InjectionDetectionConfig,
    RiskLevel,
)

config = AirTrustConfig(
    consent_gate=ConsentGateConfig(
        enabled=True,
        risk_threshold=RiskLevel.MEDIUM,
        timeout_seconds=30,
    ),
    audit_ledger=AuditLedgerConfig(
        enabled=True,
        local_path="~/.air-trust/audit-ledger.json",
    ),
    vault=VaultConfig(
        enabled=True,
        categories=["api_key", "credential", "pii"],
        ttl_seconds=86400,
    ),
    injection_detection=InjectionDetectionConfig(
        enabled=True,
        sensitivity="medium",  # low, medium, high
        block_threshold=0.8,
    ),
    gateway_url=None,  # Optional: forward to AIR Gateway
    gateway_key=None,
)

hooks = AirTrustHooks(config)
```

## EU AI Act Compliance

This trust layer addresses Articles 9, 10, 11, 12, 14, and 15 of the EU AI Act:

| Article | Component | Requirement |
|---------|-----------|-------------|
| **Art. 9** | Audit Ledger | Risk management and documentation |
| **Art. 10** | Data Vault | Data governance and protection |
| **Art. 11** | Audit Ledger | Recordkeeping and logging |
| **Art. 12** | Injection Detector | Transparency and disclosure |
| **Art. 14** | Consent Gate | Human oversight and control |
| **Art. 15** | All components | Accountability and documentation |

## Integration with Anthropic Agent SDK

The hooks integrate with Anthropic's Agent SDK lifecycle:

```python
# Hooks are called automatically:

# 1. Agent start (injection scan + tokenize input)
hooks.on_agent_start(agent_name, input_text)

# 2. Tool execution (consent check + tokenize args)
hooks.on_tool_start(tool_name, tool_args)
hooks.on_tool_end(tool_name, tool_result)

# 3. Agent completion (tokenize output)
hooks.on_agent_end(agent_name, output_text)

# 4. Messages (injection scan for user messages)
hooks.on_message(role, content)
```

## Audit Statistics

```python
# Get real-time stats
stats = hooks.get_audit_stats()
# {
#   "total_entries": 42,
#   "by_action": {"tool_start": 10, "tool_end": 10, ...},
#   "by_tool": {"read_file": 5, "write_file": 2, ...},
#   "by_risk_level": {"LOW": 20, "MEDIUM": 15, "HIGH": 7}
# }

# Get vault stats
vault_stats = hooks.get_vault_stats()
# {
#   "total_tokens": 8,
#   "by_category": {"api_key": 3, "pii": 5},
#   "enabled": true
# }

# Verify chain integrity
verification = hooks.verify_chain()
# {"valid": true, "errors": []}
```

## Error Handling

```python
from air_anthropic_trust import (
    InjectionBlockedError,
    ConsentDeniedError,
    AirTrustError,
)

try:
    hooks.on_agent_start("agent", malicious_input)
except InjectionBlockedError as e:
    print(f"Injection blocked: {e.score:.2f}")
    print(f"Patterns: {e.patterns}")

try:
    hooks.on_tool_start("exec", {})
except ConsentDeniedError as e:
    print(f"Tool blocked: {e.tool_name}")
    print(f"Risk: {e.risk_level}")
```

## Advanced Usage

### Custom Risk Classification

```python
config = AirTrustConfig(
    consent_gate=ConsentGateConfig(
        always_require=["custom_dangerous_tool"],
        never_require=["safe_helper_tool"],
    )
)
```

### Custom Detection Patterns

```python
config = AirTrustConfig(
    vault=VaultConfig(
        custom_patterns={
            "my_secret_format": r"SECRET:[A-Z0-9]{32}",
        }
    )
)
```

### Injection Sensitivity

```python
config = AirTrustConfig(
    injection_detection=InjectionDetectionConfig(
        sensitivity="high",  # More aggressive detection
        block_threshold=0.7,  # Lower threshold = more blocking
    )
)
```

## Testing

```bash
pip install air-anthropic-trust[dev]
pytest tests/
```

## Links

- **AIR Blackbox**: https://airblackbox.ai
- **Documentation**: https://airblackbox.ai/docs/anthropic
- **GitHub**: https://github.com/airblackbox/air-anthropic-trust
- **PyPI**: https://pypi.org/project/air-anthropic-trust/

## License

MIT License (c) 2026 AIR Blackbox

## Support

For issues, questions, or feedback:
- GitHub Issues: https://github.com/airblackbox/air-anthropic-trust/issues
- Email: contact@airblackbox.ai
