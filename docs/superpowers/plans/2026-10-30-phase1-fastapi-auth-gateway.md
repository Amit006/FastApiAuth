# FastAPI Auth Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the existing FastAPI POC into a production-grade auth gateway with refresh token rotation, reuse detection, absolute session timeout, and a Redis-backed token registry.

**Architecture:** The flat `main.py` is replaced by an `app/` package. Token logic lives in `services/token.py`, Redis operations in `services/redis_store.py`, Pydantic schemas in `models/auth.py`, all four auth endpoints in `routers/auth.py`, and environment config in `core/config.py`. The existing `main.py` is left intact until Task 7 is verified.

**Tech Stack:** FastAPI 0.115, PyJWT 2.9, redis-py 5.2, pydantic-settings 2.6, fakeredis 2.26 (tests only), pytest 8.3, httpx 0.27

**Spec:** `docs/superpowers/specs/2026-10-30-omnimarket-auth-design.md`

## Global Constraints
- All endpoints mount under `/api/v1/auth/`
- Status codes: `200` success, `204` logout, `401` missing/expired/invalid token, `403` reuse detected, `422` validation failure (FastAPI auto)
- Access token: HS256, 15-minute expiry, payload fields: `sub`, `type: "access"`, `exp`
- Refresh token: HS256, 24-hour rolling window, payload fields: `sub`, `type: "refresh"`, `exp`, `absolute_exp`
- `absolute_exp` set once at login (login time + 7 days), copied unchanged on every rotation — never extended
- Cookie name: `refresh_token`, flags: `HttpOnly=True`, `Secure=True`, `SameSite=Lax`, `Path=/api/v1/auth`
- CORS: `allow_credentials=True`, origins from `.env`
- No secrets hardcoded — all config from `.env`

## Review Focus
- Expired `absolute_exp` on `/refresh`: must return `401`, not rotate — test in Task 6
- Reused (already-rotated) token on `/refresh`: must return `403` and wipe ALL sessions for that user — test in Task 6
- Missing cookie on `/refresh` or `/session`: must return `401`, not `500` — test in Tasks 6 and 7
- Wrong `type` claim (e.g. access token sent to `/refresh`): must return `401` — test in Task 6
- Revoke-all must not affect other users' tokens — test in Task 4

---

## File Map

```
FastApi/
├── .env                              ← Task 1 (new)
├── requirements.txt                  ← Task 1 (replace)
├── app/
│   ├── __init__.py                   ← Task 1
│   ├── main.py                       ← Task 1
│   ├── core/
│   │   ├── __init__.py               ← Task 1
│   │   ├── config.py                 ← Task 1
│   │   └── dependencies.py           ← Task 4
│   ├── models/
│   │   ├── __init__.py               ← Task 2
│   │   └── auth.py                   ← Task 2
│   ├── services/
│   │   ├── __init__.py               ← Task 3
│   │   ├── token.py                  ← Task 3
│   │   └── redis_store.py            ← Task 4
│   └── routers/
│       ├── __init__.py               ← Task 5
│       └── auth.py                   ← Tasks 5, 6, 7
└── tests/
    ├── __init__.py                   ← Task 5
    ├── conftest.py                   ← Task 5
    ├── test_token.py                 ← Task 3
    ├── test_redis_store.py           ← Task 4
    └── test_auth.py                  ← Tasks 5, 6, 7
```

---

### Task 1: Project Scaffold & Configuration

**Files:**
- Replace: `requirements.txt`
- Create: `.env`
- Create: `app/__init__.py`
- Create: `app/core/__init__.py`
- Create: `app/core/config.py`
- Create: `app/main.py`

**Interfaces:**
- Produces: `settings` singleton from `app.core.config` — all later tasks import this

- [ ] **Step 1: Replace requirements.txt**

```
fastapi==0.115.0
uvicorn==0.32.0
pydantic-settings==2.6.1
PyJWT==2.9.0
redis==5.2.0
python-multipart==0.0.12
httpx==0.27.2
pytest==8.3.3
pytest-asyncio==0.24.0
fakeredis==2.26.1
```

- [ ] **Step 2: Install new dependencies**

```bash
.venv/Scripts/pip install -r requirements.txt
```

Expected: all packages install without conflict.

- [ ] **Step 3: Create `.env`**

```env
SECRET_KEY=change-me-in-production-use-openssl-rand-hex-32
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_HOURS=24
ABSOLUTE_SESSION_EXPIRE_DAYS=7
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://localhost:3002
```

- [ ] **Step 4: Create `app/__init__.py` and `app/core/__init__.py`** (both empty)

- [ ] **Step 5: Create `app/core/config.py`**

```python
from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List


class Settings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_HOURS: int = 24
    ABSOLUTE_SESSION_EXPIRE_DAYS: int = 7
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 0
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def split_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",")]
        return v

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
```

- [ ] **Step 6: Create `app/main.py`**

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings

app = FastAPI(title="OmniMarket Auth Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```

> Note: the auth router is added in Task 5 once it exists.

- [ ] **Step 7: Verify the app loads**

```bash
.venv/Scripts/python -c "from app.main import app; print('OK')"
```

Expected: prints `OK` with no import errors.

- [ ] **Step 8: Commit**

```bash
git add requirements.txt .env app/__init__.py app/core/__init__.py app/core/config.py app/main.py
git commit -m "feat: scaffold app package and pydantic-settings config"
```

---

### Task 2: Pydantic Models

**Files:**
- Create: `app/models/__init__.py`
- Create: `app/models/auth.py`

**Interfaces:**
- Produces: `LoginPayload`, `TokenResponse`, `SessionResponse` used by `routers/auth.py`

- [ ] **Step 1: Create `app/models/__init__.py`** (empty)

- [ ] **Step 2: Create `app/models/auth.py`**

```python
from pydantic import BaseModel


class LoginPayload(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    accessToken: str


class SessionResponse(BaseModel):
    userId: str
    username: str
    accessToken: str
    absoluteExp: int
```

- [ ] **Step 3: Verify models load**

```bash
.venv/Scripts/python -c "from app.models.auth import LoginPayload, TokenResponse, SessionResponse; print('OK')"
```

Expected: prints `OK`.

- [ ] **Step 4: Commit**

```bash
git add app/models/__init__.py app/models/auth.py
git commit -m "feat: add auth Pydantic models"
```

---

### Task 3: Token Service

**Files:**
- Create: `app/services/__init__.py`
- Create: `app/services/token.py`
- Create: `tests/__init__.py`
- Create: `tests/test_token.py`

**Interfaces:**
- Consumes: `settings` from `app.core.config`
- Produces:
  - `create_access_token(user_id: str) -> str`
  - `create_refresh_token(user_id: str, absolute_exp: int | None = None) -> tuple[str, int]`
  - `decode_token(token: str) -> dict`

- [ ] **Step 1: Write failing tests — create `tests/__init__.py`** (empty) and `tests/test_token.py`**

```python
import time
import pytest
import jwt as pyjwt
from app.services.token import create_access_token, create_refresh_token, decode_token


def test_access_token_has_correct_claims():
    token = create_access_token("user_1")
    payload = decode_token(token)
    assert payload["sub"] == "user_1"
    assert payload["type"] == "access"
    assert payload["exp"] > int(time.time())


def test_access_token_expires_in_15_minutes():
    token = create_access_token("user_1")
    payload = decode_token(token)
    expected_exp = int(time.time()) + 15 * 60
    assert abs(payload["exp"] - expected_exp) < 5  # within 5 seconds


def test_refresh_token_has_correct_claims():
    token, absolute_exp = create_refresh_token("user_1")
    payload = decode_token(token)
    assert payload["sub"] == "user_1"
    assert payload["type"] == "refresh"
    assert payload["absolute_exp"] == absolute_exp
    assert payload["exp"] <= absolute_exp


def test_refresh_token_copies_absolute_exp_unchanged():
    _, first_abs = create_refresh_token("user_1")
    token2, abs2 = create_refresh_token("user_1", absolute_exp=first_abs)
    assert abs2 == first_abs
    payload = decode_token(token2)
    assert payload["absolute_exp"] == first_abs


def test_refresh_token_exp_capped_at_absolute_exp():
    # absolute_exp only 1 hour away — rolling window (24h) must not exceed it
    absolute_exp = int(time.time()) + 3600
    token, _ = create_refresh_token("user_1", absolute_exp=absolute_exp)
    payload = decode_token(token)
    assert payload["exp"] <= absolute_exp


def test_decode_raises_on_garbage():
    with pytest.raises(pyjwt.InvalidTokenError):
        decode_token("not.a.real.token")
```

- [ ] **Step 2: Run to verify they fail**

```bash
.venv/Scripts/pytest tests/test_token.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.services.token'`

- [ ] **Step 3: Create `app/services/__init__.py`** (empty) and **`app/services/token.py`**

```python
import time
import jwt
from app.core.config import settings


def _now() -> int:
    return int(time.time())


def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "access",
        "exp": _now() + settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: str, absolute_exp: int | None = None) -> tuple[str, int]:
    now = _now()
    if absolute_exp is None:
        absolute_exp = now + settings.ABSOLUTE_SESSION_EXPIRE_DAYS * 86400
    exp = now + settings.REFRESH_TOKEN_EXPIRE_HOURS * 3600
    if exp > absolute_exp:
        exp = absolute_exp
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": exp,
        "absolute_exp": absolute_exp,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, absolute_exp


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/Scripts/pytest tests/test_token.py -v
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/services/__init__.py app/services/token.py tests/__init__.py tests/test_token.py
git commit -m "feat: add token service with access/refresh token creation and decoding"
```

---

### Task 4: Redis Token Store

**Files:**
- Create: `app/services/redis_store.py`
- Create: `app/core/dependencies.py`
- Create: `tests/test_redis_store.py`

**Interfaces:**
- Consumes: `settings` from `app.core.config`
- Produces:
  - `RedisTokenStore(client: redis.Redis)` — class
    - `.save(token: str, user_id: str, absolute_exp: int) -> None`
    - `.get(token: str) -> dict | None` — returns `{"user_id": str, "is_used": bool}` or `None`
    - `.mark_used(token: str) -> None`
    - `.revoke_all(user_id: str) -> None`
  - `get_redis_store() -> RedisTokenStore` — FastAPI dependency function

- [ ] **Step 1: Write failing tests — create `tests/test_redis_store.py`**

```python
import time
import pytest
import fakeredis
from app.services.redis_store import RedisTokenStore


@pytest.fixture
def store():
    client = fakeredis.FakeRedis(decode_responses=True)
    return RedisTokenStore(client)


def test_save_and_get(store):
    absolute_exp = int(time.time()) + 3600
    store.save("tok1", "user_1", absolute_exp)
    result = store.get("tok1")
    assert result == {"user_id": "user_1", "is_used": False}


def test_get_missing_returns_none(store):
    assert store.get("does_not_exist") is None


def test_mark_used_flips_flag(store):
    absolute_exp = int(time.time()) + 3600
    store.save("tok1", "user_1", absolute_exp)
    store.mark_used("tok1")
    assert store.get("tok1")["is_used"] is True


def test_mark_used_on_missing_does_not_raise(store):
    store.mark_used("ghost_token")  # should silently do nothing


def test_revoke_all_wipes_only_target_user(store):
    absolute_exp = int(time.time()) + 3600
    store.save("tok1", "user_1", absolute_exp)
    store.save("tok2", "user_1", absolute_exp)
    store.save("tok3", "user_2", absolute_exp)
    store.revoke_all("user_1")
    assert store.get("tok1") is None
    assert store.get("tok2") is None
    assert store.get("tok3") == {"user_id": "user_2", "is_used": False}


def test_revoke_all_on_user_with_no_tokens_does_not_raise(store):
    store.revoke_all("user_nobody")  # should silently do nothing
```

- [ ] **Step 2: Run to verify they fail**

```bash
.venv/Scripts/pytest tests/test_redis_store.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.services.redis_store'`

- [ ] **Step 3: Create `app/services/redis_store.py`**

```python
import json
import time
import redis as redis_lib


class RedisTokenStore:
    def __init__(self, client: redis_lib.Redis):
        self._r = client

    def save(self, token: str, user_id: str, absolute_exp: int) -> None:
        ttl = max(1, absolute_exp - int(time.time()))
        value = json.dumps({"user_id": user_id, "is_used": False})
        self._r.set(f"rt:{token}", value, ex=ttl)
        self._r.sadd(f"user_tokens:{user_id}", token)
        self._r.expireat(f"user_tokens:{user_id}", absolute_exp)

    def get(self, token: str) -> dict | None:
        raw = self._r.get(f"rt:{token}")
        if raw is None:
            return None
        return json.loads(raw)

    def mark_used(self, token: str) -> None:
        raw = self._r.get(f"rt:{token}")
        if raw is None:
            return
        data = json.loads(raw)
        data["is_used"] = True
        ttl = self._r.ttl(f"rt:{token}")
        self._r.set(f"rt:{token}", json.dumps(data), ex=max(1, ttl))

    def revoke_all(self, user_id: str) -> None:
        tokens = self._r.smembers(f"user_tokens:{user_id}")
        for token in tokens:
            self._r.delete(f"rt:{token}")
        self._r.delete(f"user_tokens:{user_id}")
```

- [ ] **Step 4: Create `app/core/dependencies.py`**

```python
import redis as redis_lib
from app.core.config import settings
from app.services.redis_store import RedisTokenStore


def get_redis_store() -> RedisTokenStore:
    client = redis_lib.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD or None,
        db=settings.REDIS_DB,
        decode_responses=True,
    )
    return RedisTokenStore(client)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
.venv/Scripts/pytest tests/test_redis_store.py -v
```

Expected: all 6 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add app/services/redis_store.py app/core/dependencies.py tests/test_redis_store.py
git commit -m "feat: add Redis token store with secondary user index and revoke-all support"
```

---

### Task 5: Test Infrastructure & Login Endpoint

**Files:**
- Create: `app/routers/__init__.py`
- Create: `app/routers/auth.py` (login endpoint only)
- Modify: `app/main.py` (register router)
- Create: `tests/conftest.py`
- Create: `tests/test_auth.py` (login tests only)

**Interfaces:**
- Consumes: `LoginPayload`, `TokenResponse` from `app.models.auth`; `create_access_token`, `create_refresh_token` from `app.services.token`; `RedisTokenStore` from `app.services.redis_store`; `get_redis_store` from `app.core.dependencies`
- Produces: `POST /api/v1/auth/login` → `200 TokenResponse` + `Set-Cookie: refresh_token`

- [ ] **Step 1: Create `tests/conftest.py`**

```python
import pytest
import fakeredis
from fastapi.testclient import TestClient
from app.main import app
from app.core.dependencies import get_redis_store
from app.services.redis_store import RedisTokenStore


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def store(fake_redis):
    return RedisTokenStore(fake_redis)


@pytest.fixture
def client(fake_redis):
    def override():
        return RedisTokenStore(fake_redis)

    app.dependency_overrides[get_redis_store] = override
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
```

- [ ] **Step 2: Write failing login tests — create `tests/test_auth.py`**

```python
def test_login_success_returns_access_token(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    assert resp.status_code == 200
    assert "accessToken" in resp.json()


def test_login_sets_httponly_refresh_cookie(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    assert resp.status_code == 200
    assert "refresh_token" in resp.cookies


def test_login_wrong_password_returns_401(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "wrong"},
    )
    assert resp.status_code == 401


def test_login_unknown_user_returns_401(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "secure_pass"},
    )
    assert resp.status_code == 401


def test_login_missing_fields_returns_422(client):
    resp = client.post("/api/v1/auth/login", json={})
    assert resp.status_code == 422
```

- [ ] **Step 3: Run to verify they fail**

```bash
.venv/Scripts/pytest tests/test_auth.py -v
```

Expected: 404 errors (router not registered yet).

- [ ] **Step 4: Create `app/routers/__init__.py`** (empty)

- [ ] **Step 5: Create `app/routers/auth.py`** (login endpoint only)

```python
from fastapi import APIRouter, HTTPException, Response, Cookie, Depends
from app.models.auth import LoginPayload, TokenResponse, SessionResponse
from app.services.token import create_access_token, create_refresh_token, decode_token
from app.services.redis_store import RedisTokenStore
from app.core.dependencies import get_redis_store
import jwt

router = APIRouter()

# Mock user store — replace with a real database in production
_USERS = {
    "developer": {"password": "secure_pass", "user_id": "user_456"},
}


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginPayload,
    response: Response,
    store: RedisTokenStore = Depends(get_redis_store),
):
    user = _USERS.get(payload.username)
    if not user or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    user_id = user["user_id"]
    refresh_token, absolute_exp = create_refresh_token(user_id)
    store.save(refresh_token, user_id, absolute_exp)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/api/v1/auth",
    )

    return TokenResponse(accessToken=create_access_token(user_id))
```

- [ ] **Step 6: Register the router in `app/main.py`**

Add at the bottom of `app/main.py`:

```python
from app.routers import auth as auth_router

app.include_router(auth_router.router, prefix="/api/v1/auth", tags=["auth"])
```

- [ ] **Step 7: Run login tests to verify they pass**

```bash
.venv/Scripts/pytest tests/test_auth.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 8: Commit**

```bash
git add app/routers/__init__.py app/routers/auth.py app/main.py tests/conftest.py tests/test_auth.py
git commit -m "feat: add login endpoint with refresh token cookie and test infrastructure"
```

---

### Task 6: Refresh Endpoint

**Files:**
- Modify: `app/routers/auth.py` (add refresh endpoint)
- Modify: `tests/test_auth.py` (add refresh tests)

**Interfaces:**
- Consumes: `refresh_token` cookie; `decode_token`; `RedisTokenStore.get`, `.mark_used`, `.save`, `.revoke_all`; `create_access_token`, `create_refresh_token`
- Produces: `POST /api/v1/auth/refresh` → `200 TokenResponse` + rotated cookie, or `401`/`403`

- [ ] **Step 1: Write failing refresh tests — append to `tests/test_auth.py`**

```python
def test_refresh_success_returns_new_access_token(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200
    assert "accessToken" in resp.json()


def test_refresh_rotates_cookie(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    original_token = client.cookies.get("refresh_token")
    client.post("/api/v1/auth/refresh")
    assert client.cookies.get("refresh_token") != original_token


def test_refresh_no_cookie_returns_401(client):
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401


def test_refresh_reuse_returns_403_and_revokes_all(client, fake_redis):
    from app.services.redis_store import RedisTokenStore
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    original_token = client.cookies.get("refresh_token")
    # First rotation — consumes original_token
    client.post("/api/v1/auth/refresh")
    # Replay the original (already-used) token
    client.cookies.set("refresh_token", original_token)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 403
    # All tokens for user_456 must be gone
    store = RedisTokenStore(fake_redis)
    assert store.get(original_token) is None


def test_refresh_wrong_token_type_returns_401(client):
    from app.services.token import create_access_token
    access_token = create_access_token("user_456")
    client.cookies.set("refresh_token", access_token)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401


def test_refresh_expired_absolute_exp_returns_401(client, fake_redis):
    import time
    import jwt as pyjwt
    from app.core.config import settings
    from app.services.redis_store import RedisTokenStore

    past = int(time.time()) - 1
    token = pyjwt.encode(
        {
            "sub": "user_456",
            "type": "refresh",
            "exp": int(time.time()) + 3600,   # rolling window still valid
            "absolute_exp": past,              # absolute session expired
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    store = RedisTokenStore(fake_redis)
    store.save(token, "user_456", past + 10)
    client.cookies.set("refresh_token", token)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401
```

- [ ] **Step 2: Run to verify they fail**

```bash
.venv/Scripts/pytest tests/test_auth.py::test_refresh_success_returns_new_access_token -v
```

Expected: `404 Not Found` (endpoint does not exist yet).

- [ ] **Step 3: Add the refresh endpoint to `app/routers/auth.py`**

Add after the `login` function:

```python
@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    response: Response,
    refresh_token: str | None = Cookie(None),
    store: RedisTokenStore = Depends(get_redis_store),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Session token missing.")

    try:
        payload = decode_token(refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type.")

    user_id: str = payload["sub"]
    absolute_exp: int = payload["absolute_exp"]

    import time as _time
    if _time.time() > absolute_exp:
        store.revoke_all(user_id)
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    metadata = store.get(refresh_token)
    if metadata is None:
        raise HTTPException(status_code=401, detail="Session invalid or revoked.")

    if metadata["is_used"]:
        store.revoke_all(user_id)
        response.delete_cookie(key="refresh_token", path="/api/v1/auth")
        raise HTTPException(
            status_code=403,
            detail="Security breach detected. All sessions have been revoked.",
        )

    store.mark_used(refresh_token)

    new_refresh_token, _ = create_refresh_token(user_id, absolute_exp=absolute_exp)
    store.save(new_refresh_token, user_id, absolute_exp)

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/api/v1/auth",
    )

    return TokenResponse(accessToken=create_access_token(user_id))
```

- [ ] **Step 4: Run refresh tests to verify they pass**

```bash
.venv/Scripts/pytest tests/test_auth.py -k "refresh" -v
```

Expected: all 6 refresh tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/routers/auth.py tests/test_auth.py
git commit -m "feat: add refresh endpoint with token rotation and reuse detection"
```

---

### Task 7: Session & Logout Endpoints

**Files:**
- Modify: `app/routers/auth.py` (add session and logout endpoints)
- Modify: `tests/test_auth.py` (add session and logout tests)

**Interfaces:**
- Consumes: `refresh_token` cookie; `decode_token`; `RedisTokenStore.get`, `.revoke_all`; `create_access_token`; `SessionResponse`
- Produces:
  - `GET /api/v1/auth/session` → `200 SessionResponse` or `401`
  - `POST /api/v1/auth/logout` → `204` or `401`

- [ ] **Step 1: Write failing session and logout tests — append to `tests/test_auth.py`**

```python
def test_session_returns_user_and_access_token(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    resp = client.get("/api/v1/auth/session")
    assert resp.status_code == 200
    data = resp.json()
    assert data["userId"] == "user_456"
    assert data["username"] == "developer"
    assert "accessToken" in data
    assert "absoluteExp" in data


def test_session_no_cookie_returns_401(client):
    resp = client.get("/api/v1/auth/session")
    assert resp.status_code == 401


def test_session_wrong_token_type_returns_401(client):
    from app.services.token import create_access_token
    client.cookies.set("refresh_token", create_access_token("user_456"))
    resp = client.get("/api/v1/auth/session")
    assert resp.status_code == 401


def test_logout_returns_204(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    resp = client.post("/api/v1/auth/logout")
    assert resp.status_code == 204


def test_logout_clears_cookie(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    client.post("/api/v1/auth/logout")
    # Session should now be invalid
    resp = client.get("/api/v1/auth/session")
    assert resp.status_code == 401


def test_logout_no_session_returns_401(client):
    resp = client.post("/api/v1/auth/logout")
    assert resp.status_code == 401
```

- [ ] **Step 2: Run to verify they fail**

```bash
.venv/Scripts/pytest tests/test_auth.py -k "session or logout" -v
```

Expected: `404 Not Found` (endpoints do not exist yet).

- [ ] **Step 3: Add session and logout endpoints to `app/routers/auth.py`**

Add after the `refresh` function:

```python
# Reverse lookup: user_id → username (mirrors _USERS at the top of the file)
_USER_ID_TO_NAME = {v["user_id"]: k for k, v in _USERS.items()}


@router.get("/session", response_model=SessionResponse)
async def session(
    refresh_token: str | None = Cookie(None),
    store: RedisTokenStore = Depends(get_redis_store),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Session token missing.")

    try:
        payload = decode_token(refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type.")

    user_id: str = payload["sub"]
    absolute_exp: int = payload["absolute_exp"]

    import time as _time
    if _time.time() > absolute_exp:
        raise HTTPException(status_code=401, detail="Session expired.")

    if store.get(refresh_token) is None:
        raise HTTPException(status_code=401, detail="Session invalid or revoked.")

    return SessionResponse(
        userId=user_id,
        username=_USER_ID_TO_NAME.get(user_id, user_id),
        accessToken=create_access_token(user_id),
        absoluteExp=absolute_exp,
    )


@router.post("/logout", status_code=204)
async def logout(
    response: Response,
    refresh_token: str | None = Cookie(None),
    store: RedisTokenStore = Depends(get_redis_store),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No active session.")

    try:
        payload = decode_token(refresh_token)
        store.revoke_all(payload["sub"])
    except jwt.InvalidTokenError:
        pass  # Token already invalid — still clear the cookie

    response.delete_cookie(key="refresh_token", path="/api/v1/auth")
```

- [ ] **Step 4: Run the full test suite**

```bash
.venv/Scripts/pytest tests/ -v
```

Expected: all tests PASS. Output should show ~23 tests passing.

- [ ] **Step 5: Start the server and verify OpenAPI docs load**

```bash
.venv/Scripts/uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs` — confirm four endpoints appear under the `auth` tag:
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/logout`

- [ ] **Step 6: Commit**

```bash
git add app/routers/auth.py tests/test_auth.py
git commit -m "feat: add session and logout endpoints, complete Phase 1 auth gateway"
```

---

## What's Next

Phase 1 is complete and testable standalone. The next plans (to be written separately) are:

- **Phase 2:** Turborepo monorepo scaffold + `@omnimarket/auth`, `@omnimarket/ui`, `@omnimarket/tsconfig`, `@omnimarket/eslint-config` packages
- **Phase 3:** `apps/storefront` — SSG/ISR/SSR pages
- **Phase 4:** `apps/dashboard` — middleware, streaming, SWR, Route Handlers
- **Phase 5:** `apps/creators` — PPR, Server Actions, Parallel/Intercepting routes
