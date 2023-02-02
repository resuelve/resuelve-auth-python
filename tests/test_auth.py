import time

import pytest
from resuelve_auth.auth import build_token, validate_token
from resuelve_auth.exceptions import ExpiredToken, InvalidSignature, MalformedToken


def test_create_and_decode_token():
    secret = "this is a secret phrase"
    token = build_token(secret, meta={"user": 1})

    metadata = validate_token(secret, token)

    assert metadata == {"user": 1}


def test_raise_error_for_expired_token():
    secret = "this is a secret phrase"
    token = build_token(secret)
    time.sleep(2)

    with pytest.raises(ExpiredToken):
        validate_token(secret, token, ttl=1)


def test_raise_error_for_invalid_signature():
    secret = "this is a secret phrase"
    token = build_token(secret)

    encoded_data, _sign = token.split(".")

    _encoded_data, sign = build_token("another secret").split(".")
    # put another signature
    token = f"{encoded_data}.{sign}"

    with pytest.raises(InvalidSignature):
        validate_token(secret, token)


def test_raise_error_when_token_is_malformed():
    with pytest.raises(MalformedToken):
        validate_token("secret", "something that doesn't match a valid token format")
