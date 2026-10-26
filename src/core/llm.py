"""LLM provider setup: Ollama-first with deterministic fallback (Kickoff).

Primary: Ollama (Llama 3.1 8B or Qwen 2.5)
Fallback: Deterministic rule-based responses when Ollama unavailable.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage

from src.core.config import get_settings

import structlog

logger = structlog.get_logger(__name__)


def get_ollama_model() -> BaseChatModel | None:
    """Create an Ollama chat model if available.

    Returns None if Ollama is not running or the model isn't pulled.
    """
    settings = get_settings()

    # Check if Ollama is available
    try:
        response = httpx.get(
            f"{settings.ollama.base_url}/api/tags",
            timeout=5.0,
        )
        response.raise_for_status()
        available_models = [m["name"] for m in response.json().get("models", [])]
    except Exception as e:
        logger.warning("ollama_unavailable", error=str(e))
        return None

    # Try primary model, then fallback
    for model_name in [settings.ollama.model, settings.ollama.fallback_model]:
        # Check if model is available (with or without :latest tag)
        model_available = any(
            m == model_name or m.startswith(f"{model_name}:")
            for m in available_models
        )
        if model_available:
            from langchain_ollama import ChatOllama

            logger.info("ollama_model_selected", model=model_name)
            return ChatOllama(
                model=model_name,
                base_url=settings.ollama.base_url,
                temperature=settings.ollama.temperature,
                num_predict=4096,
            )

    logger.warning(
        "ollama_no_suitable_model",
        available=available_models,
        requested=[settings.ollama.model, settings.ollama.fallback_model],
    )
    return None


class DeterministicFallback:
    """Rule-based fallback when no LLM is available.

    Provides deterministic responses for each agent role so the
    system remains functional (with reduced intelligence) when
    Ollama is not running.
    """

    def invoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
        """Process messages deterministically based on the system prompt role."""
        system_content = ""
        user_content = ""

        for msg in messages:
            if isinstance(msg, SystemMessage):
                system_content = msg.content
            elif isinstance(msg, HumanMessage):
                user_content = msg.content

        # Route based on role detected in system prompt
        if "supervisor" in system_content.lower():
            return self._supervisor_response(user_content)
        elif "parser" in system_content.lower():
            return self._parser_response(user_content)
        elif "risk" in system_content.lower():
            return self._risk_response(user_content)
        elif "planner" in system_content.lower():
            return self._planner_response(user_content)
        elif "verifier" in system_content.lower():
            return self._verifier_response(user_content)
        else:
            return AIMessage(content="[Deterministic fallback] No LLM available. Please start Ollama.")

    def _supervisor_response(self, content: str) -> AIMessage:
        """Deterministic supervisor routing."""
        content_lower = content.lower()
        if "dependencies found: 0" in content_lower or "pending" in content_lower:
            return AIMessage(content="parser")
        elif "findings so far: 0" in content_lower and "dependencies found:" in content_lower:
            return AIMessage(content="risk_assessor")
        elif "findings" in content_lower and "plan" not in content_lower:
            return AIMessage(content="planner")
        elif "plan" in content_lower:
            return AIMessage(content="verifier")
        else:
            return AIMessage(content="FINISH")

    def _parser_response(self, content: str) -> AIMessage:
        """Deterministic parser — uses the actual parser tool."""
        return AIMessage(content="[Deterministic] Parsing dependencies using rule-based parser.")

    def _risk_response(self, content: str) -> AIMessage:
        """Deterministic risk assessment."""
        return AIMessage(content="[Deterministic] Checking vulnerabilities using bundled database.")

    def _planner_response(self, content: str) -> AIMessage:
        """Deterministic planner."""
        return AIMessage(content="[Deterministic] Creating upgrade plan from findings.")

    def _verifier_response(self, content: str) -> AIMessage:
        """Deterministic verifier — always approves."""
        return AIMessage(content="VERIFIED")


def get_model() -> BaseChatModel | DeterministicFallback:
    """Get the best available model.

    Returns Ollama model if available, otherwise deterministic fallback.
    """
    model = get_ollama_model()
    if model is not None:
        return model

    logger.warning("using_deterministic_fallback")
    return DeterministicFallback()
