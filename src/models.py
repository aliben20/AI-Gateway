from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from enum import Enum

class Provider(str, Enum):
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    GOOGLE = "google"

class ModelDiscoveryRequest(BaseModel):
    model: str
    provider: Optional[Provider] = None

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[Dict[str, str]]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1000
    provider: Optional[str] = None

    @field_validator('temperature')
    @classmethod
    def validate_temperature(cls, v):
        if not (0 <= v <= 2):
            raise ValueError('temperature must be between 0 and 2')
        return v

class KeyCreate(BaseModel):
    name: str
    provider: Provider
    key: str
    is_active: bool = True

class KeyResponse(BaseModel):
    id: int
    name: str
    provider: Provider
    is_active: bool
    usage_count: int
