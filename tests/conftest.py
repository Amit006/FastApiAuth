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
    with TestClient(app, raise_server_exceptions=True, base_url="https://testserver") as c:
        yield c
    app.dependency_overrides.clear()
