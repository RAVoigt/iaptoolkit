from __future__ import annotations
from abc import ABC
from abc import abstractmethod
import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())

import typing as t
from urllib.parse import ParseResult
from urllib.parse import urlparse

from kvcommon.logger import get_logger

from iaptoolkit.constants import DEFAULT_USE_AUTH_HEADER
from iaptoolkit import headers
from iaptoolkit.exceptions import ServiceAccountTokenException
from iaptoolkit.tokens.oauth2 import OAuth2
from iaptoolkit.tokens.oauth2.datastore_oauth2 import TokenDatastore_OAuth2
from iaptoolkit.tokens.oidc import OIDC
from iaptoolkit.tokens.structs import ResultAddTokenHeader
from iaptoolkit.tokens.structs import TokenStruct

from iaptoolkit.tokens.structs import TokenStruct

from iaptoolkit.utils.urls import is_url_safe_for_token

LOG = get_logger("iaptk")


class IAPToolkit(ABC):
    """
    Abstract base class wrapping up core iaptoolkit functionality in a single interface
    In practice, you should use IAPToolkit_OIDC or IAPToolkit_OAuth2 for
        OIDC(ServiceAccounts) or OAuth2(Users) respectively.
    """

    _GOOGLE_IAP_CLIENT_ID: str

    def __init__(self, google_iap_client_id: str) -> None:
        self._GOOGLE_IAP_CLIENT_ID = google_iap_client_id

    @staticmethod
    def sanitize_request_headers(request_headers: dict) -> dict:
        return headers.sanitize_request_headers(request_headers)

    @abstractmethod
    def get_token(self, refresh_token: str | None = None, bypass_cached: bool = False) -> TokenStruct:
        raise NotImplementedError()

    def get_token_str(self, refresh_token: str | None = None, bypass_cached: bool = False) -> str:
        struct = self.get_token(refresh_token=refresh_token, bypass_cached=bypass_cached)
        return struct.id_token

    def get_token_and_add_to_headers(
        self,
        request_headers: dict,
        use_auth_header: bool = DEFAULT_USE_AUTH_HEADER,
        refresh_token: str | None = None,
        bypass_cached: bool = False,
    ) -> bool:
        """
        Retrieves an auth token and inserts it into the supplied request_headers dict.
        request_headers is modified in-place

        Params:
            request_headers: dict of headers to insert into
            use_oauth2: Use OAuth2.0 credentials and respective token, else use OIDC (default)
                As a general guideline, OIDC is the assumed default approach for ServiceAccounts.
            use_auth_header: If true, use the 'Authorization' header instead of 'Proxy-Authorization'.
                Note that in this case 'Proxy-Authorization' will be used instead if 'Authorization'
                already exists in headers.
            refresh_token: Refresh token for OAuth2.0 (Unused by OIDC)

        Returns:
            True if token retrieved from cache, False if fresh from API


        """
        token_refresh_struct = self.get_token(refresh_token=refresh_token, bypass_cached=bypass_cached)
        id_token = token_refresh_struct.id_token
        from_cache = token_refresh_struct.from_cache

        headers.add_token_to_request_headers(
            request_headers=request_headers,
            id_token=id_token,
            use_auth_header=use_auth_header,
        )

        return from_cache

    @staticmethod
    def is_url_safe_for_token(
        url: str | ParseResult,
        valid_domains: t.Optional[t.List[str] | t.Set[str] | t.Tuple[str]] = None,
    ):
        if not isinstance(url, ParseResult):
            url = urlparse(url)

        return is_url_safe_for_token(url_parts=url, allowed_domains=valid_domains)

    def check_url_and_add_token_header(
        self,
        url: str | ParseResult,
        request_headers: dict,
        valid_domains: t.List[str] | None = None,
        use_auth_header: bool = DEFAULT_USE_AUTH_HEADER,
        refresh_token: str | None = None,
        bypass_cached: bool = False,
    ) -> ResultAddTokenHeader:
        """
        Checks that the supplied URL is valid (i.e.; in valid_domains) and if so, retrieves a
        token and adds it to request_headers.

        i.e.; A convenience wrapper with logging for is_url_safe_for_token() and get_token_and_add_to_headers()

        Params:
            url: URL string or urllib.ParseResult to check for validity
            request_headers: Dict of headers to insert into
            valid_domains: List of domains to validate URL against
            use_auth_header: If true, use the 'Authorization' header instead of 'Proxy-Authorization' for IAP
            refresh_token: Refresh token for OAuth2.0 (Unused by OIDC)
        """

        if self.is_url_safe_for_token(url=url, valid_domains=valid_domains):
            token_is_fresh = self.get_token_and_add_to_headers(
                request_headers=request_headers,
                use_auth_header=use_auth_header,
                refresh_token=refresh_token,
                bypass_cached=bypass_cached,
            )
            return ResultAddTokenHeader(token_added=True, token_is_fresh=token_is_fresh)
        else:
            LOG.warning(
                "URL is not approved: %s - Token will not be added to headers. Valid domains are: %s",
                url,
                valid_domains,
            )
            return ResultAddTokenHeader(token_added=False, token_is_fresh=False)


class IAPToolkit_OIDC(IAPToolkit):
    """
    OIDC-only implementation of IAPToolkit
    """

    _interface: OIDC

    def __init__(self, google_iap_client_id: str) -> None:
        super().__init__(google_iap_client_id)
        self._interface = OIDC(iap_client_id=google_iap_client_id)

    def get_token(self, refresh_token: str | None = None, bypass_cached: bool = False) -> TokenStruct:
        try:
            return self._interface.get_token(iap_client_id=self._GOOGLE_IAP_CLIENT_ID, bypass_cached=bypass_cached)
        except ServiceAccountTokenException as ex:
            LOG.debug(ex)
            raise


class IAPToolkit_OAuth2(IAPToolkit):
    """
    Convenience subclass of IAPToolkit for scenarios where OAuth2 will always be used, never OIDC
    """

    _GOOGLE_CLIENT_ID: str
    _GOOGLE_CLIENT_SECRET: str
    _interface: OAuth2

    def __init__(
        self,
        google_iap_client_id: str,
        google_client_id: str,
        google_client_secret: str,
    ) -> None:
        super().__init__(google_iap_client_id=google_iap_client_id)
        self._GOOGLE_CLIENT_ID = google_client_id
        self._GOOGLE_CLIENT_SECRET = google_client_secret
        self._interface = OAuth2(
            iap_client_id=google_iap_client_id,
            client_id=google_client_id,
            client_secret=google_client_secret,
        )

    def get_refresh_token_from_auth_code(self, auth_code: str, redirect_uri: str) -> TokenStruct:
        return self._interface.get_refresh_token_from_auth_code(auth_code=auth_code, redirect_uri=redirect_uri)

    def get_refresh_token(self) -> TokenStruct | None:
        refresh_token = self._interface.get_stored_refresh_token()
        if refresh_token and refresh_token.expired:
            return None
        return refresh_token

    def get_token(self, refresh_token: TokenStruct | str, bypass_cached: bool = False) -> TokenStruct | None:
        token_expired = False
        id_token: TokenStruct | None = None

        if bypass_cached:
            token_expired = True
        else:
            id_token: TokenStruct | None = self._interface._get_stored_token()
            token_expired = not id_token or id_token.expired

        if not id_token or token_expired:
            if isinstance(refresh_token, TokenStruct):
                refresh_token = refresh_token.id_token
            id_token = self._interface.get_id_token_from_refresh_token(refresh_token=refresh_token)

        return id_token

    def check_url_and_add_token_header(
        self,
        url: str | ParseResult,
        request_headers: dict,
        refresh_token: str,
        valid_domains: t.List[str] | None = None,
        use_auth_header: bool = DEFAULT_USE_AUTH_HEADER,
    ) -> ResultAddTokenHeader:
        return super().check_url_and_add_token_header(
            url=url,
            request_headers=request_headers,
            valid_domains=valid_domains,
            use_auth_header=use_auth_header,
            refresh_token=refresh_token,
        )
