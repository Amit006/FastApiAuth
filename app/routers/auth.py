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
        path="/",
    )

    return TokenResponse(accessToken=create_access_token(user_id))


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
        response.delete_cookie(key="refresh_token", path="/")
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
        path="/",
    )

    return TokenResponse(accessToken=create_access_token(user_id))


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

    response.delete_cookie(key="refresh_token", path="/")
