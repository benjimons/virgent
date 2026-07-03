"""Pluggable reasoning layer.

The engine talks to a :class:`ReasoningProvider` interface so enterprises can
swap the backing model (Anthropic first-party API, Bedrock, Vertex, or a mock
for air-gapped/audit runs) without touching the audit, policy, or redaction
machinery — which all live in the engine, *around* this interface.

Providers deliberately return content hashes alongside the text so the audit
log can bind each call to exact inputs/outputs without storing them raw.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import sha256_hex

DEFAULT_MODEL = "claude-opus-4-8"


@dataclass
class LLMResult:
    text: str
    model: str
    stop_reason: str = "end_turn"
    input_tokens: int = 0
    output_tokens: int = 0
    prompt_sha256: str = ""
    response_sha256: str = ""

    def usage_dict(self) -> dict:
        return {
            "model": self.model,
            "stop_reason": self.stop_reason,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "prompt_sha256": self.prompt_sha256,
            "response_sha256": self.response_sha256,
        }


class ReasoningProvider(ABC):
    name: str = "abstract"

    @abstractmethod
    def complete(self, prompt: str, system: str | None = None, max_tokens: int = 16000) -> LLMResult:
        """Run a single completion. ``prompt`` is already redacted by the engine."""


class AnthropicProvider(ReasoningProvider):
    """Claude API backend using the official ``anthropic`` SDK.

    Streams responses (timeout protection for long outputs) and uses adaptive
    thinking. The SDK is imported lazily so the rest of Virgent works in
    environments where the ``llm`` extra is not installed.
    """

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, client=None):
        self.model = model
        if client is None:
            try:
                import anthropic
            except ImportError as e:  # pragma: no cover
                raise RuntimeError(
                    "The 'anthropic' package is required for AnthropicProvider. "
                    "Install it with: pip install 'virgent[llm]'"
                ) from e
            client = anthropic.Anthropic()
        self.client = client

    def complete(self, prompt: str, system: str | None = None, max_tokens: int = 16000) -> LLMResult:
        kwargs: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "thinking": {"type": "adaptive"},
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        with self.client.messages.stream(**kwargs) as stream:
            message = stream.get_final_message()
        text = "".join(block.text for block in message.content if block.type == "text")
        return LLMResult(
            text=text,
            model=message.model,
            stop_reason=message.stop_reason or "end_turn",
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
            prompt_sha256=sha256_hex((system or "") + "\x00" + prompt),
            response_sha256=sha256_hex(text),
        )


@dataclass
class MockProvider(ReasoningProvider):
    """Deterministic provider for tests and air-gapped audit runs.

    Returns ``responses`` in order (repeating the last one) and records every
    prompt it receives.
    """

    responses: list[str] = field(default_factory=lambda: ["[]"])
    name: str = "mock"
    calls: list[dict] = field(default_factory=list)

    def complete(self, prompt: str, system: str | None = None, max_tokens: int = 16000) -> LLMResult:
        self.calls.append({"prompt": prompt, "system": system, "max_tokens": max_tokens})
        idx = min(len(self.calls) - 1, len(self.responses) - 1)
        text = self.responses[idx]
        return LLMResult(
            text=text,
            model="mock",
            input_tokens=len(prompt) // 4,
            output_tokens=len(text) // 4,
            prompt_sha256=sha256_hex((system or "") + "\x00" + prompt),
            response_sha256=sha256_hex(text),
        )
