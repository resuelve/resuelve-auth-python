import base64
import binascii
import hashlib
import hmac
import json
from datetime import datetime

from . import exceptions


def build_token(
    secret: str, meta: dict = None, service: str = "", role: str = ""
) -> str:
    """
    Create a token to access Resuelve services

    Implement resuelve auth token generation
    """
    # we need to make this here instead of using a default argument
    # because python hold state in function definition
    if meta is None:
        meta = {}

    data = {
        "service": service,
        "role": role,
        # timestamp should be in milliseconds
        "timestamp": int(datetime.utcnow().timestamp() * 1000),
        "meta": meta,
    }

    message, signature = _encode(secret.encode(), data)

    return f"{message}.{signature}"


def validate_token(secret: str, token: str, ttl=None) -> dict:
    """
    Validate token using SECRET key

    It will validate signature and optionally the TTL in case
    is provided, TTL should be in seconds
    """
    try:
        [b64_data, sign] = token.split(".")

        decoded_data = json.loads(base64.b64decode(b64_data.encode()))

        _, sign_to_verify = _encode(secret.encode(), decoded_data)

        if sign != sign_to_verify:
            raise exceptions.InvalidSignature("Invalid signature")

        if ttl:
            # ttl is defined in seconds and timestamp in miliseconds
            limit_time = (ttl * 1000) + decoded_data["timestamp"]
            if int(datetime.utcnow().timestamp() * 1000) > limit_time:
                raise exceptions.ExpiredToken(
                    f"Timestamp expired for TTL: {ttl} seconds"
                )

        return decoded_data["meta"]
    except (binascii.Error, ValueError):
        # binascii.Error will raise in case there is a base64 error
        # ValueError will raise in case the token doesn't have a separation dot in it
        raise exceptions.MalformedToken("Provided token wasn't able to be parsed")


def _encode(secret: bytes, data: dict) -> (str, str):
    """
    Create a signature for the given data and secret
    """
    # we need to define custom separators because by default json.dumps
    # put a space after them that causes to generate a different signature
    # we need ensure_Sir=False because data could contain special characters
    # and that could invalidate the signature
    message = base64.b64encode(
        json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode()
    )

    hash_ = hmac.HMAC(key=secret, msg=message, digestmod=hashlib.sha256)
    signature = hash_.hexdigest().upper()

    return message.decode(), signature
