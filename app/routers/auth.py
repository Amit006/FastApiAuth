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

# Reverse lookup: user_id → username
_USER_ID_TO_NAME = {v["user_id"]: k for k, v in _USERS.items()}


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
