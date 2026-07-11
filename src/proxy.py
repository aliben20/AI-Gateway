import httpx
import asyncio
from typing import Optional
from fastapi import HTTPException, Request

from src.config import settings
from src.key_manager import KeyManager, decrypt_key
from src.database import get_db, RequestLog


class AIGatewayProxy:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60.0)
        self.providers = settings.PROVIDERS

    async def forward_request(self, request: Request, provider: Optional[str] = None):
        body = await request.json()
        model = body.get("model")
        if not model:
            raise HTTPException(400, "Model is required")

        if not provider:
            provider = await self.discover_provider(model)

        if not provider:
            raise HTTPException(404, f"No provider found for model: {model}")

        db = next(get_db())
        key_manager = KeyManager(db)
        api_key = key_manager.rotate_key(provider, settings.KEY_ROTATION_STRATEGY)

        if not api_key:
            raise HTTPException(503, f"No active keys for provider: {provider}")

        decrypted_key = decrypt_key(api_key.encrypted_key)

        provider_config = self.providers.get(provider)
        if not provider_config:
            raise HTTPException(400, f"Provider {provider} not configured")

        url = f"{provider_config['api_base']}/chat/completions"
        headers = {
            "Authorization": f"Bearer {decrypted_key}",
            "Content-Type": "application/json"
        }

        try:
            start_time = asyncio.get_event_loop().time()
            response = await self.client.post(url, json=body, headers=headers)
            response_time = asyncio.get_event_loop().time() - start_time

            await self.log_request(
                provider=provider,
                model=model,
                status_code=response.status_code,
                response_time=response_time
            )

            return response.json()

        except httpx.TimeoutException:
            raise HTTPException(504, "Provider timeout")
        except Exception as e:
            raise HTTPException(500, f"Provider error: {str(e)}")

    async def discover_provider(self, model: str) -> Optional[str]:
        for provider_name, provider_config in self.providers.items():
            if model in provider_config.get("models", []):
                return provider_name
        return None

    async def log_request(self, provider: str, model: str, status_code: int, response_time: float):
        db = next(get_db())
        log = RequestLog(
            endpoint="/v1/chat/completions",
            provider=provider,
            model=model,
            status_code=status_code,
            response_time=response_time
        )
        db.add(log)
        db.commit()
