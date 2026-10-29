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


def test_refresh_success_returns_new_access_token(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200
    assert "accessToken" in resp.json()


def test_refresh_rotates_cookie(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    original_token = login_resp.cookies["refresh_token"]
    refresh_resp = client.post("/api/v1/auth/refresh")
    new_token = refresh_resp.cookies["refresh_token"]
    assert new_token != original_token


def test_refresh_no_cookie_returns_401(client):
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401


def test_refresh_reuse_returns_403_and_revokes_all(client, fake_redis):
    from app.services.redis_store import RedisTokenStore
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    original_token = login_resp.cookies["refresh_token"]
    # First rotation — marks original_token as is_used=True, issues new token
    client.post("/api/v1/auth/refresh")
    # Replay the original (already-used) token by replacing the client cookie
    del client.cookies["refresh_token"]
    client.cookies.set("refresh_token", original_token)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 403
    store = RedisTokenStore(fake_redis)
    assert store.get(original_token) is None


def test_refresh_wrong_token_type_returns_401(client):
    from app.services.token import create_access_token
    access_token = create_access_token("user_456")
    client.cookies.set("refresh_token", access_token)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401


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


def test_logout_clears_cookie_and_invalidates_session(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    client.post("/api/v1/auth/logout")
    resp = client.get("/api/v1/auth/session")
    assert resp.status_code == 401


def test_logout_no_session_returns_401(client):
    resp = client.post("/api/v1/auth/logout")
    assert resp.status_code == 401


def test_login_cookie_has_max_age(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie", "")
    assert "max-age=" in set_cookie.lower()


def test_refresh_cookie_has_max_age(client):
    client.post(
        "/api/v1/auth/login",
        json={"username": "developer", "password": "secure_pass"},
    )
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200
    set_cookie = resp.headers.get("set-cookie", "")
    assert "max-age=" in set_cookie.lower()


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
            "exp": int(time.time()) + 3600,
            "absolute_exp": past,
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    store = RedisTokenStore(fake_redis)
    store.save(token, "user_456", past + 10)
    client.cookies.set("refresh_token", token)
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401
