from os import getenv
from typing import Any, Optional

from django.conf import settings


def _env_or_setting(key: str, default: Any) -> Any:
    return getenv(key) or getattr(settings, key, default)


# the name of GET argument to contain the token
JWT_QUERYSTRING_ARG = _env_or_setting("REQUEST_TOKEN_QUERYSTRING", "rt")  # type: str

# the fixed expiration check on Session tokens
JWT_SESSION_TOKEN_EXPIRY = int(_env_or_setting("REQUEST_TOKEN_EXPIRY", 10))  # type: int

# Set the default 403 template value
FOUR03_TEMPLATE = _env_or_setting(
    "REQUEST_TOKEN_403_TEMPLATE", None
)  # type: Optional[str]

# log all InvalidTokenErrors
LOG_TOKEN_ERRORS = _env_or_setting(
    "REQUEST_TOKEN_LOG_TOKEN_ERRORS", "True"
).lower() in (
    "true",
    "1",
)  # noqa

DEFAULT_MAX_USES = _env_or_setting("REQUEST_TOKEN_DEFAULT_MAX_USES", 10)

# Enable use of session tokens - disabled by default
ENABLE_SESSION_TOKENS = bool(
    _env_or_setting("REQUEST_TOKEN_ENABLE_SESSION_TOKENS", False)
)
