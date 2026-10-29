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
    store.mark_used("ghost_token")


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
    store.revoke_all("user_nobody")
