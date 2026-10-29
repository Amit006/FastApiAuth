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
