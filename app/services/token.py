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
