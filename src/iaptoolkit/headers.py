import typing as t
from urllib.parse import urlparse
from kvcommon import logger

from iaptoolkit.constants import GOOGLE_IAP_AUTH_HEADER
from iaptoolkit.constants import GOOGLE_IAP_AUTH_HEADER_PROXY
from iaptoolkit.tokens import get_token_for_google_service_account as get_token
from iaptoolkit.tokens.structs import ResultAddTokenHeader
from iaptoolkit.utils.urls import is_url_safe_for_token
from iaptoolkit.vars import IAPTOOLKIT_USE_AUTH_HEADER


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
    Returns A COPY of the dict with sensitive k/v pairs replaced. Does NOT modify in-place/by-reference.
    """
    log_safe_headers = headers.copy()

    _sanitize_request_header(log_safe_headers, GOOGLE_IAP_AUTH_HEADER)
    _sanitize_request_header(log_safe_headers, GOOGLE_IAP_AUTH_HEADER_PROXY)
    _sanitize_request_header(log_safe_headers, "X-Goog-Iap-Jwt-Assertion")

    return log_safe_headers


def add_token_to_request_headers(request_headers: dict, use_oauth2: bool) -> bool:
    """
    Adds Bearer token to headers dict. Modifies dict in-place.
    Returns True if added token is a fresh one, or False if token is from cache
    """
    # TODO: Make this less google-specific, or move it to a google-specific implementation
    # TODO: oauth2

    token_refresh_struct = get_token()
    id_token: str = token_refresh_struct.id_token
    auth_header_str = "Bearer {}".format(id_token)

    auth_header_key = GOOGLE_IAP_AUTH_HEADER_PROXY
    # Don't override an existing authorization header if there is one
    # Google IAP supports passing the token in 'Proxy-Authorization' header if `Authorization` is already in use
    if IAPTOOLKIT_USE_AUTH_HEADER:
        if GOOGLE_IAP_AUTH_HEADER not in request_headers:
            request_headers[GOOGLE_IAP_AUTH_HEADER] = auth_header_str
            auth_header_key = GOOGLE_IAP_AUTH_HEADER
        else:
            LOG.debug(
                "IAPTOOLKIT_USE_AUTH_HEADER is set but 'Authorization' header already exists. "
                "Adding IAP token to Proxy-Authorization header only."
            )

    request_headers[auth_header_key] = auth_header_str

    return token_refresh_struct.token_is_new


def check_url_and_add_token_header(
    url: str,
    request_headers: dict,
    use_oauth2: bool = False,
    valid_domains: t.Optional[t.List[str]] = None,
) -> ResultAddTokenHeader:
    """Prevent inadvertently sending private tokens to arbitrary locations.
    Returns:
        True, True: Adding token was allowed and token is fresh
        True, False: Adding token was allowed and token is from cache
        False, False: Adding token was not allowed
    """
    url_parts = urlparse(url)

    # Verify that the url's domain is one we allow before adding a token
    if is_url_safe_for_token(url_parts, valid_domains):
        token_is_fresh = add_token_to_request_headers(request_headers, use_oauth2)
        return ResultAddTokenHeader(token_added=True, token_is_fresh=token_is_fresh)
    else:
        LOG.warn(
            "URL is not approved: %s - Token will not be added to headers. Valid domains are: %s",
            url,
            valid_domains,
        )
        return ResultAddTokenHeader(token_added=False, token_is_fresh=False)
