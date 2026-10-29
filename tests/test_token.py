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
    assert abs(payload["exp"] - expected_exp) < 5


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
    absolute_exp = int(time.time()) + 3600
    token, _ = create_refresh_token("user_1", absolute_exp=absolute_exp)
    payload = decode_token(token)
    assert payload["exp"] <= absolute_exp


def test_decode_raises_on_garbage():
    with pytest.raises(pyjwt.InvalidTokenError):
        decode_token("not.a.real.token")
