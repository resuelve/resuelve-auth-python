class ResuelveAuthError(Exception):
    """
    Base exception class to group specific ones
    """


class MalformedToken(ResuelveAuthError):
    """
    Error while parsing token value
    """


class InvalidSignature(ResuelveAuthError):
    """
    Signature couldn't be verified
    """


class ExpiredToken(ResuelveAuthError):
    """
    Timestamp value is already too old
    """
