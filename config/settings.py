"""Typed environment configuration, loaded once and imported everywhere else."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen3-coder:30b"
    LLM_TEMPERATURE: float = 0.1
    # Ollama's runtime context window defaults small (often 2048-4096) regardless of what
    # the model itself supports (this model reports 262144) — verified live 2026-07-16 that
    # the default was too small to hold the system prompt + 13 tool schemas + one tool
    # result of modest size (5877 tokens > a 4096 default), so every ChatOllama instantiation
    # passes this explicitly rather than trusting the server's default.
    OLLAMA_NUM_CTX: int = 8192

    # Safety
    MAX_REQ_PER_SEC: int = 10
    MIN_REPRO_COUNT: int = 3
    MIN_CONFIDENCE_TO_AUTOCONFIRM: int = 7

    # Paths
    SESSIONS_DIR: str = "sessions"
    REPORTS_DIR: str = "reports"
    PAYLOADS_DIR: str = "config/payloads"

    # UI
    UI_HOST: str = "0.0.0.0"
    UI_PORT: int = 7860


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
