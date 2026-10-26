"""Core configuration and settings for ChainGuard."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    """Application environment."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class OllamaSettings(BaseSettings):
    """Ollama-specific configuration."""

    base_url: str = Field(default="http://localhost:11434", description="Ollama API base URL")
    model: str = Field(default="llama3.1:8b", description="Primary model for agents")
    fallback_model: str = Field(
        default="qwen2.5:7b", description="Fallback model if primary unavailable"
    )
    temperature: float = Field(default=0.1, ge=0.0, le=2.0, description="Model temperature")
    timeout: int = Field(default=120, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Max retries for model calls")


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    url: str = Field(
        default="sqlite+aiosqlite:///data/chainguard.db", description="Database URL"
    )
    checkpoint_db: str = Field(
        default="data/checkpoints.db", description="SQLite checkpointer database path"
    )


class AuthSettings(BaseSettings):
    """Authentication configuration."""

    secret_key: str = Field(
        default="chainguard-dev-secret-key-change-in-production",
        description="JWT secret key",
    )
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=60, description="Token expiration in minutes"
    )


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration."""

    requests_per_minute: int = Field(default=30, description="Max requests per minute per user")
    tokens_per_minute: int = Field(
        default=50000, description="Max tokens per minute per user"
    )


class AgentSettings(BaseSettings):
    """Agent-specific configuration."""

    max_iterations: int = Field(
        default=6,
        ge=1,
        le=20,
        description="Hard cap on ReAct loop iterations",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Max Verifier → Planner retry cycles",
    )
    context_window_size: int = Field(
        default=4096, description="Sliding window size for context pruning (tokens)"
    )
    token_budget: int = Field(default=8192, description="Max token budget per agent call")


class GuardrailSettings(BaseSettings):
    """Guardrail configuration."""

    enable_injection_detection: bool = Field(
        default=True, description="Detect prompt injection in uploaded files"
    )
    enable_pii_redaction: bool = Field(
        default=True, description="Redact secrets and PII from files and logs"
    )
    max_file_size_mb: int = Field(default=10, description="Max upload file size in MB")
    allowed_extensions: list[str] = Field(
        default=[".txt", ".toml", ".json", ".cfg", ".ini"],
        description="Allowed file extensions for upload",
    )


class FeatureFlags(BaseSettings):
    """Feature flags for optional functionality."""

    enable_osv_lookup: bool = Field(
        default=False, description="Enable live OSV.dev vulnerability lookup"
    )
    enable_llama_guard: bool = Field(
        default=False, description="Enable Llama Guard for output safety"
    )
    enable_pdf_export: bool = Field(default=False, description="Enable PDF export")
    enable_package_json: bool = Field(
        default=False, description="Enable package.json parsing"
    )


class Settings(BaseSettings):
    """Root application settings."""

    model_config = {"env_prefix": "CHAINGUARD_", "env_nested_delimiter": "__"}

    app_name: str = "ChainGuard"
    version: str = "0.1.0"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = Field(default=True, description="Debug mode")

    # Sub-configurations
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    guardrails: GuardrailSettings = Field(default_factory=GuardrailSettings)
    features: FeatureFlags = Field(default_factory=FeatureFlags)

    # Paths
    data_dir: Path = Field(default=Path("data"), description="Data directory")
    log_level: str = Field(default="INFO", description="Logging level")

    @field_validator("data_dir", mode="before")
    @classmethod
    def ensure_data_dir(cls, v: str | Path) -> Path:
        """Ensure data directory exists."""
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path


# Singleton
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create application settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
