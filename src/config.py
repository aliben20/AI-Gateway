import os
from pydantic_settings import BaseSettings
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet

class Settings(BaseSettings):
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-here")
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "")

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:////tmp/gateway.db")

    PROVIDERS: Dict[str, Dict[str, Any]] = {
        "openai": {
            "api_base": "https://api.openai.com/v1",
            "models": ["gpt-4", "gpt-3.5-turbo"]
        },
        "deepseek": {
            "api_base": "https://api.deepseek.com/v1",
            "models": ["deepseek-chat", "deepseek-coder"]
        },
        "google": {
            "api_base": "https://generativelanguage.googleapis.com/v1",
            "models": ["gemini-pro"]
        }
    }

    KEY_ROTATION_STRATEGY: str = "round-robin"

    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "gateway.log"

    model_config = {"env_file": ".env"}

settings = Settings()
