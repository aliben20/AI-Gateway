from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os, json, time
from datetime import datetime

from src.config import settings
from src.database import get_db, engine, Base, APIKey, RequestLog
from src.proxy import AIGatewayProxy
from src.key_manager import KeyManager, generate_gateway_key, validate_gateway_key
from src.algorithms import ALGORITHMS_LIST, ALGORITHM_PARAMS, CATEGORIES, run_algorithm
from src.models import KeyCreate, KeyResponse, Provider
from src.auth import verify_token, create_access_token, verify_token_optional
from src.rate_limiter import rate_limiter
from src.analytics import router as analytics_router
from src.logging import logger

try:
    Base.metadata.create_all(bind=engine)
except Exception:
    pass  # Table creation may fail on readonly filesystems (Vercel)

app = FastAPI(
    title="AI Gateway API",
    description="بوابة وسيطة شفافة لإدارة مفاتيح الذكاء الاصطناعي",
    version="1.0.0"
)

@app.on_event("startup")
async def seed_initial_data():
    try:
        from src.database import SessionLocal, APIKey
        db = SessionLocal()
        existing = db.query(APIKey).filter(APIKey.provider == "flatkey").first()
        if not existing:
            key = APIKey(
                name="FlatKey Main",
                provider="flatkey",
                key="sk-QrkSeNQUTBfr7a3oiS7QutYsQHTqwNmuTmaH6QU6baufuz15",
                is_active=True,
                usage_count=0
            )
            db.add(key)
            db.commit()
            logger.info("Seeded FlatKey API key")
        db.close()
    except Exception as e:
        logger.warning(f"Could not seed FlatKey key: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analytics_router)

proxy = AIGatewayProxy()

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(_BASE_DIR, "templates")
# Fallback for Vercel: try current working directory
if not os.path.isdir(TEMPLATES_DIR):
    TEMPLATES_DIR = os.path.join(os.getcwd(), "templates")
INDEX_HTML = os.path.join(TEMPLATES_DIR, "index.html")


@app.get("/")
async def root():
    return FileResponse(INDEX_HTML)


@app.post("/api/login")
async def login(body: dict):
    username = body.get("username")
    password = body.get("password")
    if username == "admin" and password == "admin123":
        token = create_access_token({"sub": username, "role": "admin"})
        logger.info(f"User '{username}' logged in")
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(401, "Invalid credentials")


@app.post("/v1/chat/completions")
async def chat_completion(
    request: Request,
    provider: str = None,
    _=Depends(rate_limiter)
):
    return await proxy.forward_request(request, provider)


@app.post("/api/keys", response_model=KeyResponse)
async def add_key(
    key_data: KeyCreate,
    db: Session = Depends(get_db),
    user=Depends(verify_token)
):
    key_manager = KeyManager(db)
    new_key = key_manager.add_key(
        name=key_data.name,
        provider=key_data.provider.value,
        key=key_data.key
    )
    logger.info(f"Key '{key_data.name}' added for provider '{key_data.provider.value}' by {user.get('sub')}")
    return {
        "id": new_key.id,
        "name": new_key.name,
        "provider": new_key.provider,
        "is_active": new_key.is_active,
        "usage_count": new_key.usage_count
    }


@app.get("/api/keys")
async def list_keys(
    provider: str = None,
    db: Session = Depends(get_db),
    user=Depends(verify_token)
):
    key_manager = KeyManager(db)
    keys = key_manager.get_active_keys(provider)
    return [
        {
            "id": k.id,
            "name": k.name,
            "provider": k.provider,
            "is_active": k.is_active,
            "usage_count": k.usage_count
        }
        for k in keys
    ]


@app.delete("/api/keys/{key_id}")
async def delete_key(
    key_id: int,
    db: Session = Depends(get_db),
    user=Depends(verify_token)
):
    key_manager = KeyManager(db)
    success = key_manager.deactivate_key(key_id)
    if not success:
        raise HTTPException(404, f"Key {key_id} not found")
    logger.info(f"Key {key_id} deactivated by {user.get('sub')}")
    return {"message": f"Key {key_id} deactivated successfully"}


# ==================== Key Generation (FlatKey) ====================
@app.get("/api/flatkey/keys/generate")
async def generate_key_endpoint():
    """توليد مفتاح بتنسيق gw_xxxxxx_xxxx_xxxxxxxxxxxxxxxxxxxxxxxx"""
    new_key = generate_gateway_key()
    return {
        "key": new_key,
        "format": "gw_xxxxxx_xxxx_xxxxxxxxxxxxxxxxxxxxxxxx",
        "length": len(new_key)
    }


@app.post("/api/flatkey/keys/generate-and-save")
async def generate_and_save_key(body: dict, db: Session = Depends(get_db), user=Depends(verify_token)):
    """توليد مفتاح وحفظه مباشرة"""
    name = body.get("name", "")
    provider = body.get("provider", "openai")
    if not name:
        raise HTTPException(400, "الاسم مطلوب")

    new_key_value = generate_gateway_key()
    key_manager = KeyManager(db)
    new_key = key_manager.add_key(name=name, provider=provider, key=new_key_value)
    logger.info(f"Generated gateway key '{name}' for {provider} by {user.get('sub')}")
    return {
        "id": new_key.id,
        "key": new_key_value,
        "name": name,
        "provider": provider,
        "message": "✅ تم توليد وحفظ المفتاح بنجاح"
    }


@app.post("/api/flatkey/keys/validate")
async def validate_key_endpoint(body: dict):
    """التحقق من صحة تنسيق المفتاح"""
    key = body.get("key", "")
    is_valid = validate_gateway_key(key)
    return {
        "key": key,
        "is_valid": is_valid,
        "message": "✅ تنسيق صحيح" if is_valid else "❌ تنسيق غير صحيح"
    }


# ==================== Algorithms Generator ====================
@app.get("/api/algorithms/list")
async def list_algorithms():
    return {"algorithms": ALGORITHMS_LIST, "total": len(ALGORITHMS_LIST), "params": ALGORITHM_PARAMS, "categories": CATEGORIES}

@app.get("/api/algorithms/categories")
async def list_categories():
    return {"categories": CATEGORIES}

@app.post("/api/algorithms/generate")
async def generate_algorithm(body: dict):
    algo_id = body.get("algorithm_id", "")
    params = body.get("params", {})
    try:
        result = run_algorithm(algo_id, params)
        return {"status": "success", "algorithm": result, "generated_at": datetime.utcnow().isoformat()}
    except Exception as e:
        raise HTTPException(400, f"فشل التوليد: {str(e)}")


# ==================== Auth alias ====================
@app.post("/api/auth/login")
async def auth_login(body: dict):
    username = body.get("email", body.get("username"))
    password = body.get("password")
    if username == "admin@gateway.com" and password == "admin123":
        token = create_access_token({"sub": username, "role": "admin"})
        logger.info(f"User '{username}' logged in")
        return {"access_token": token, "token_type": "bearer", "user": {"name": "Admin", "email": username, "role": "admin"}}
    raise HTTPException(401, "Invalid credentials")


# ==================== Providers ====================
PROVIDER_NAMES = {
    "openai": "OpenAI", "deepseek": "DeepSeek", "google": "Google",
    "anthropic": "Anthropic", "mistral": "Mistral", "cohere": "Cohere",
    "groq": "Groq", "together": "Together"
}
PROVIDER_COLORS = {
    "openai": "#10a37f", "deepseek": "#4f46e5", "google": "#4285f4",
    "anthropic": "#d97706", "mistral": "#f59e0b", "cohere": "#22c55e",
    "groq": "#ef4444", "together": "#6366f1"
}


def _build_providers():
    default_endpoints = [
        {"id": "ep_chat", "type": "chat", "path": "/v1/chat/completions"},
        {"id": "ep_models", "type": "models", "path": "/v1/models"},
        {"id": "ep_embeddings", "type": "embeddings", "path": "/v1/embeddings"},
        {"id": "ep_images", "type": "images", "path": "/v1/images/generations"},
    ]
    return [
        {
            "id": str(i + 1), "name": PROVIDER_NAMES.get(k, k.title()),
            "baseUrl": cfg.get("api_base", ""), "isActive": False,
            "priority": 0, "color": PROVIDER_COLORS.get(k, "#6366f1"),
            "authHeader": "Authorization", "tokenFormat": "Bearer Token",
            "protocol": "Transparent",
            "endpoints": default_endpoints,
            "models": [{"id": f"m{i}_{mi}", "name": m} for mi, m in enumerate(cfg.get("models", []))],
            "_count": {"requestLogs": 0}, "successRate": round(95 + (hash(k) % 50) / 10, 1),
            "lastUsedAt": None
        }
        for i, (k, cfg) in enumerate(settings.PROVIDERS.items())
    ]


PROVIDER_STORE = _build_providers()


@app.get("/api/providers")
async def list_providers():
    return PROVIDER_STORE


@app.post("/api/providers")
async def create_provider(body: dict, user=Depends(verify_token)):
    new_id = str(len(PROVIDER_STORE) + 1)
    provider = {
        "id": new_id,
        "name": body.get("name", ""),
        "baseUrl": body.get("baseUrl", ""),
        "isActive": True,
        "priority": body.get("priority", 0),
        "color": body.get("color", "#6366f1"),
        "authHeader": body.get("authHeader", "Authorization"),
        "tokenFormat": body.get("tokenFormat", "Bearer Token"),
        "protocol": body.get("protocol", "Transparent"),
        "endpoints": body.get("endpoints", [
            {"id": "ep_chat", "type": "chat", "path": "/v1/chat/completions"},
            {"id": "ep_models", "type": "models", "path": "/v1/models"},
        ]),
        "models": body.get("models", []),
        "_count": {"requestLogs": 0},
        "successRate": 100.0,
        "lastUsedAt": None
    }
    PROVIDER_STORE.append(provider)
    logger.info(f"Provider '{body.get('name')}' added by {user.get('sub')}")
    return provider


@app.patch("/api/providers/{provider_id}")
async def update_provider(provider_id: str, body: dict, user=Depends(verify_token)):
    for p in PROVIDER_STORE:
        if p["id"] == provider_id:
            for key in ["name", "baseUrl", "isActive", "priority", "color",
                         "authHeader", "tokenFormat", "protocol", "endpoints", "models"]:
                if key in body:
                    p[key] = body[key]
            return p
    raise HTTPException(404, "Provider not found")


@app.delete("/api/providers/{provider_id}")
async def delete_provider(provider_id: str, user=Depends(verify_token)):
    for i, p in enumerate(PROVIDER_STORE):
        if p["id"] == provider_id:
            PROVIDER_STORE.pop(i)
            return {"message": "Provider deleted"}
    raise HTTPException(404, "Provider not found")


# ==================== Routes (FlatKey) ====================
_ROUTES_STORE = []
_ROUTES_PATH = None

def _routes_db():
    global _ROUTES_STORE, _ROUTES_PATH
    if _ROUTES_STORE:
        return _ROUTES_STORE
    try:
        _ROUTES_PATH = os.path.join(settings.DATABASE_DIR, "routes.json")
        if os.path.exists(_ROUTES_PATH):
            with open(_ROUTES_PATH) as f:
                _ROUTES_STORE = json.load(f)
    except Exception:
        pass
    return _ROUTES_STORE

def _save_routes():
    try:
        with open(_ROUTES_PATH, "w") as f:
            json.dump(_ROUTES_STORE, f, indent=2)
    except Exception:
        pass

@app.get("/api/routes")
async def list_routes():
    return _routes_db()

@app.post("/api/routes")
async def create_route(body: dict, user=Depends(verify_token)):
    routes = _routes_db()
    route = {
        "id": "r_" + str(int(time.time() * 1000)),
        "name": body.get("name", ""),
        "path": body.get("path", "/"),
        "method": body.get("method", "POST"),
        "provider": body.get("provider", ""),
        "key": body.get("key", ""),
        "isActive": True,
        "createdAt": datetime.utcnow().isoformat()
    }
    routes.append(route)
    _save_routes()
    return route

@app.patch("/api/routes/{route_id}")
async def update_route(route_id: str, body: dict, user=Depends(verify_token)):
    routes = _routes_db()
    for r in routes:
        if r["id"] == route_id:
            for key in ["name", "path", "method", "provider", "key", "isActive"]:
                if key in body:
                    r[key] = body[key]
            _save_routes()
            return r
    raise HTTPException(404, "Route not found")

@app.delete("/api/routes/{route_id}")
async def delete_route(route_id: str, user=Depends(verify_token)):
    routes = _routes_db()
    for i, r in enumerate(routes):
        if r["id"] == route_id:
            routes.pop(i)
            _save_routes()
            return {"message": "Route deleted"}
    raise HTTPException(404, "Route not found")

# ==================== Logs ====================
@app.get("/api/logs")
async def list_logs(
    limit: int = 50,
    offset: int = 0,
    success: str = None,
    model: str = "",
    db: Session = Depends(get_db)
):
    query = db.query(RequestLog).order_by(RequestLog.created_at.desc())
    if success is not None:
        if success.lower() == "true":
            query = query.filter(RequestLog.status_code < 400)
        elif success.lower() == "false":
            query = query.filter(RequestLog.status_code >= 400)
    if model:
        query = query.filter(RequestLog.model.ilike(f"%{model}%"))

    total = query.count()
    logs = query.offset(offset).limit(limit).all()

    return {
        "logs": [
            {
                "id": log.id,
                "success": log.status_code < 400,
                "model": log.model,
                "providerName": log.provider,
                "endpointType": "chat",
                "statusCode": log.status_code or 200,
                "durationMs": round((log.response_time or 0) * 1000, 1),
                "retried": 0,
                "createdAt": log.created_at.isoformat() if log.created_at else None
            }
            for log in logs
        ],
        "total": total
    }


# ==================== SPA catch-all (must be last) ====================
@app.get("/{path:path}")
async def spa_fallback(path: str):
    return FileResponse(INDEX_HTML)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )
