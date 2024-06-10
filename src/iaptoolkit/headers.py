import typing as t
from urllib.parse import urlparse
from kvcommon import logger

from iaptoolkit.constants import GOOGLE_IAP_AUTH_HEADER
from iaptoolkit.constants import GOOGLE_IAP_AUTH_HEADER_PROXY

LOG = logger.get_logger("iaptk")


def _sanitize_request_header(headers_dict: dict, header_key: str):
    auth_header = headers_dict.get(header_key, None)
    if auth_header:
        # TODO: Handle multiple tokens (e.g.; "Bearer <token1>, Bearer  <token2>") properly
        if "Bearer" in auth_header:
            headers_dict[header_key] = "Bearer <token_hidden>"
        elif "Basic" in auth_header:
            headers_dict[header_key] = "Basic <basic_auth_hidden>"
        else:
            headers_dict[header_key] = "<contents_hidden>"


def sanitize_request_headers(headers: dict) -> dict:
    """
    Sanitizes a headers dict to remove sensitive strings for logging purposes.

    Returns:
        A COPY of the dict with sensitive k/v pairs replaced. Does NOT modify in-place/by-reference.
    """
    log_safe_headers = headers.copy()

    _sanitize_request_header(log_safe_headers, GOOGLE_IAP_AUTH_HEADER)
    _sanitize_request_header(log_safe_headers, GOOGLE_IAP_AUTH_HEADER_PROXY)
    _sanitize_request_header(log_safe_headers, "X-Goog-Iap-Jwt-Assertion")

    return log_safe_headers


def add_token_to_request_headers(
    request_headers: dict, id_token: str, use_auth_header: bool = False
) -> dict:
    """
    Adds Bearer token to headers dict. Modifies dict in-place.
    Returns True if added token is a fresh one, or False if token is from cache

    Params:
        request_headers: Existing dict of request headers to mutate
        use_auth_header: If True (default), use 'Authorization' header instead of 'Proxy-Authorization'

    Returns:
        True if the added token is newly-retrieved
        False if the added token is from cache
    """
    # TODO: Make this less google-specific, or move it to a google-specific implementation

    auth_header_str = "Bearer {}".format(id_token)

    # Use 'Proxy-Authorization' header by default
    auth_header_key = GOOGLE_IAP_AUTH_HEADER_PROXY

    if use_auth_header:
        # Default to use of 'Authorization' header instead of 'Proxy-Authorization'

        # Don't override an existing authorization header if there is one
        # Google IAP supports passing the token in 'Proxy-Authorization' header if
        # `Authorization` is already in use
        if GOOGLE_IAP_AUTH_HEADER not in request_headers:
            request_headers[GOOGLE_IAP_AUTH_HEADER] = auth_header_str
            auth_header_key = GOOGLE_IAP_AUTH_HEADER
        else:
            LOG.debug(
                "'use_auth_header' is True but 'Authorization' header already exists. "
                "Adding IAP token to Proxy-Authorization header only."
            )

    request_headers[auth_header_key] = auth_header_str

    return request_headers
