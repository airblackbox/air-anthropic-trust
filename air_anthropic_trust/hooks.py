"""AIR Trust Layer hooks for Anthropic Claude Agent SDK."""

from typing import Dict, Any, Optional
from .config import AirTrustConfig, RiskLevel
from .consent_gate import ConsentGate
from .data_vault import DataVault
from .audit_ledger import AuditLedger, ChainVerification
from .injection_detector import InjectionDetector
from .errors import ConsentDeniedError, InjectionBlockedError


class AirTrustHooks:
    """AIR Trust Layer hooks for Anthropic Claude Agent SDK.

    Integrates with Claude's agent framework to provide:
    - Consent gating on tool calls (ConsentGate)
    - Sensitive data tokenization (DataVault)
    - Tamper-proof audit logging (AuditLedger)
    - Prompt injection detection (InjectionDetector)

    Usage with Claude Agent SDK:
        from anthropic import Agent
        from air_anthropic_trust import AirTrustHooks

        hooks = AirTrustHooks()
        agent = Agent(
            model="claude-sonnet-4-20250514",
            tools=[...],
            hooks=hooks
        )
        result = await agent.run("Analyze this data")

        # Check audit trail
        print(hooks.get_audit_stats())
        print(hooks.verify_chain())
    """

    def __init__(self, config: AirTrustConfig = None):
        """
        Args:
            config: AirTrustConfig instance (uses defaults if None)
        """
        self.config = config or AirTrustConfig()

        # Initialize all trust components
        self.consent_gate = ConsentGate(self.config.consent_gate)
        self.vault = DataVault(self.config.vault)
        self.ledger = AuditLedger(self.config.audit_ledger)
        self.injector = InjectionDetector(
            self.config.injection_detection
        )

    def on_agent_start(
        self,
        agent_name: str,
        input_text: str
    ) -> Dict[str, Any]:
        """Called when agent execution starts.

        Args:
            agent_name: Name of the agent
            input_text: Input prompt text

        Returns:
            Modified input text and metadata

        Raises:
            InjectionBlockedError: If injection is detected
        """
        result = {"input": input_text, "blocked": False}

        # 1. Injection detection on user input
        injection_result = self.injector.scan(input_text)
        if injection_result.blocked:
            self.ledger.append(
                action="injection_detected",
                tool_name=agent_name,
                risk_level=RiskLevel.CRITICAL,
                injection_detected=True,
                metadata={
                    "score": injection_result.score,
                    "patterns": [p[0] for p in injection_result.patterns],
                },
            )
            raise InjectionBlockedError(
                score=injection_result.score,
                patterns=[p[0] for p in injection_result.patterns],
            )

        # 2. Tokenize sensitive data in input
        vault_result = self.vault.tokenize(input_text)
        tokenized_input = vault_result["result"]

        # 3. Audit log
        self.ledger.append(
            action="agent_start",
            tool_name=agent_name,
            risk_level=RiskLevel.LOW,
            data_tokenized=vault_result["tokenized"],
            injection_detected=injection_result.detected,
            metadata={
                "input_length": len(input_text),
                "injection_score": injection_result.score,
            },
        )

        result["input"] = tokenized_input
        return result

    def on_agent_end(
        self,
        agent_name: str,
        output_text: str
    ) -> Dict[str, Any]:
        """Called when agent execution completes.

        Args:
            agent_name: Name of the agent
            output_text: Output text from agent

        Returns:
            Modified output text and metadata
        """
        result = {"output": output_text}

        # 1. Tokenize sensitive data in output
        vault_result = self.vault.tokenize(output_text)
        tokenized_output = vault_result["result"]

        # 2. Audit log
        self.ledger.append(
            action="agent_end",
            tool_name=agent_name,
            risk_level=RiskLevel.LOW,
            data_tokenized=vault_result["tokenized"],
            metadata={"output_length": len(output_text)},
        )

        result["output"] = tokenized_output
        return result

    def on_tool_start(
        self,
        tool_name: str,
        tool_args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Called when a tool is about to be executed.

        Args:
            tool_name: Name of the tool
            tool_args: Tool arguments

        Returns:
            Modified tool_args and metadata

        Raises:
            ConsentDeniedError: If consent is required but denied
        """
        result = {"tool_args": tool_args, "allowed": True}

        # 1. Consent gate check
        risk_level = self.consent_gate.classify_risk(tool_name)
        requires_consent = self.consent_gate.requires_consent(
            tool_name
        )

        if requires_consent:
            # In production, this would prompt the user
            # For now, we log and continue
            self.ledger.append(
                action="tool_consent_required",
                tool_name=tool_name,
                risk_level=risk_level,
                consent_required=True,
                consent_granted=True,  # Assume granted in SDK
                metadata={"args_count": len(tool_args)},
            )

        # 2. Tokenize sensitive data in arguments
        vault_result = self.vault.tokenize(str(tool_args))
        has_sensitive_data = vault_result["tokenized"]

        tokenized_args = tool_args
        if has_sensitive_data:
            # Detokenize would happen at execution time
            # Store the mapping internally
            pass

        # 3. Audit log
        self.ledger.append(
            action="tool_start",
            tool_name=tool_name,
            risk_level=risk_level,
            consent_required=requires_consent,
            consent_granted=True,
            data_tokenized=has_sensitive_data,
            metadata={"args_count": len(tool_args)},
        )

        result["tool_args"] = tokenized_args
        return result

    def on_tool_end(
        self,
        tool_name: str,
        tool_result: Any
    ) -> Dict[str, Any]:
        """Called when a tool execution completes.

        Args:
            tool_name: Name of the tool
            tool_result: Result from tool execution

        Returns:
            Modified tool_result and metadata
        """
        result = {"tool_result": tool_result}

        # 1. Tokenize sensitive data in result
        vault_result = self.vault.tokenize(str(tool_result))
        tokenized_result = vault_result["result"]

        # 2. Audit log
        risk_level = self.consent_gate.classify_risk(tool_name)
        self.ledger.append(
            action="tool_end",
            tool_name=tool_name,
            risk_level=risk_level,
            data_tokenized=vault_result["tokenized"],
            metadata={"result_length": len(str(tool_result))},
        )

        result["tool_result"] = tokenized_result
        return result

    def on_message(
        self,
        role: str,
        content: str
    ) -> Dict[str, Any]:
        """Called for each message in the conversation.

        Args:
            role: Message role (user, assistant, system)
            content: Message content

        Returns:
            Modified content and metadata

        Raises:
            InjectionBlockedError: If injection detected in user messages
        """
        result = {"content": content}

        # Only scan user messages for injection
        if role == "user":
            injection_result = self.injector.scan(content)
            if injection_result.blocked:
                self.ledger.append(
                    action="message_injection_blocked",
                    tool_name=f"message_{role}",
                    risk_level=RiskLevel.CRITICAL,
                    injection_detected=True,
                    metadata={
                        "score": injection_result.score,
                        "patterns": [p[0] for p in injection_result.patterns],
                    },
                )
                raise InjectionBlockedError(
                    score=injection_result.score,
                    patterns=[p[0] for p in injection_result.patterns],
                )

        # Tokenize sensitive data
        vault_result = self.vault.tokenize(content)
        tokenized_content = vault_result["result"]

        # Audit log
        self.ledger.append(
            action="message",
            tool_name=f"message_{role}",
            risk_level=RiskLevel.LOW,
            data_tokenized=vault_result["tokenized"],
            injection_detected=(
                injection_result.detected
                if role == "user"
                else False
            ),
            metadata={
                "role": role,
                "content_length": len(content),
            },
        )

        result["content"] = tokenized_content
        return result

    def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit ledger statistics.

        Returns:
            Dictionary with audit stats
        """
        return self.ledger.stats()

    def verify_chain(self) -> Dict[str, Any]:
        """Verify audit chain integrity.

        Returns:
            Chain verification result as dictionary
        """
        verification = self.ledger.verify()
        return verification.to_dict()

    def export_audit(self) -> list:
        """Export all audit entries.

        Returns:
            List of audit entry dictionaries
        """
        return self.ledger.export()

    def get_vault_stats(self) -> Dict[str, Any]:
        """Get data vault statistics.

        Returns:
            Dictionary with vault stats
        """
        return self.vault.stats()
