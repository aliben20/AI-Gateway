import time
from collections import defaultdict
from fastapi import Request, HTTPException


class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests: dict = defaultdict(list)

    async def __call__(self, request: Request):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60

        self.requests[client_ip] = [t for t in self.requests[client_ip] if t > window_start]

        if len(self.requests[client_ip]) >= self.requests_per_minute:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({self.requests_per_minute} requests per minute)"
            )

        self.requests[client_ip].append(now)
        return True


rate_limiter = RateLimiter(requests_per_minute=60)
