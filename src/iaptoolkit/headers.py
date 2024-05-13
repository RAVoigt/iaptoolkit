import typing as t
from urllib.parse import urlparse
from kvcommon import logger

from iaptoolkit.constants import GOOGLE_IAP_AUTH_HEADER
from iaptoolkit.constants import GOOGLE_IAP_AUTH_HEADER_PROXY
from iaptoolkit.tokens import get_token_for_google_service_account
from iaptoolkit.tokens.structs import ResultAddTokenHeader
from iaptoolkit.utils.urls import is_url_safe_for_token
from iaptoolkit.vars import IAPTOOLKIT_USE_AUTH_HEADER
from iaptoolkit.vars import GOOGLE_IAP_CLIENT_ID

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


def add_token_to_request_headers(request_headers: dict, use_oauth2: bool, iap_client_id: str) -> bool:
    """
    Adds Bearer token to headers dict. Modifies dict in-place.
    Returns True if added token is a fresh one, or False if token is from cache
    """
    # TODO: Make this less google-specific, or move it to a google-specific implementation
    # TODO: oauth2

    token_refresh_struct = get_token_for_google_service_account(iap_client_id=iap_client_id)
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


