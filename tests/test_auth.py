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
