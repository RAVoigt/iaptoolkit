from __future__ import annotations

from abc import ABC, abstractmethod
import datetime
import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())

import typing as t
from urllib.parse import ParseResult
from urllib.parse import urlparse

from kvcommon.logger import get_logger

from iaptoolkit import headers
from iaptoolkit.exceptions import ServiceAccountTokenException
from iaptoolkit.tokens.base import BaseTokenInterface
from iaptoolkit.tokens.oauth2 import OAuth2
from iaptoolkit.tokens.oidc import OIDC
from iaptoolkit.tokens.structs import ResultAddTokenHeader
from iaptoolkit.tokens.structs import TokenRefreshStruct
from iaptoolkit.tokens.structs import TokenStructOAuth2
from iaptoolkit.utils.urls import is_url_safe_for_token

LOG = get_logger("iaptk")


class IAPToolkit(ABC):
    """
    Abstract base class wrapping up core iaptoolkit functionality in a single interface

    In practice, you should use IAPToolkit_OIDC or IAPToolkit_OAuth2 for
        OIDC(ServiceAccounts) or OAuth2(Users) respectively.
    """

    _GOOGLE_IAP_CLIENT_ID: str
    _interface: BaseTokenInterface

    def __init__(self, google_iap_client_id: str) -> None:
        self._GOOGLE_IAP_CLIENT_ID = google_iap_client_id

    @staticmethod
    def sanitize_request_headers(request_headers: dict) -> dict:
        return headers.sanitize_request_headers(request_headers)

    @abstractmethod
    def get_token(
        self, refresh_token: str | None = None, bypass_cached: bool = False
    ) -> TokenRefreshStruct:
        raise NotImplementedError()

    def get_token_str(self, refresh_token: str | None = None, bypass_cached: bool = False) -> str:
        struct = self.get_token(refresh_token=refresh_token, bypass_cached=bypass_cached)
        return struct.id_token

    def get_token_and_add_to_headers(
        self, request_headers: dict, use_auth_header: bool = False, refresh_token: str | None = None
    ) -> bool:
        """
        Retrieves an auth token and inserts it into the supplied request_headers dict.
        request_headers is modified in-place

        Params:
            request_headers: dict of headers to insert into
            use_oauth2: Use OAuth2.0 credentials and respective token, else use OIDC (default)
                As a general guideline, OIDC is the assumed default approach for ServiceAccounts.
            use_auth_header: If true, use the 'Authorization' header instead of 'Proxy-Authorization'
            refresh_token: Refresh token for OAuth2.0 (Unused by OIDC)
        """
        token_refresh_struct = self.get_token(refresh_token=refresh_token)

        headers.add_token_to_request_headers(
            request_headers=request_headers,
            id_token=token_refresh_struct.id_token,
            use_auth_header=use_auth_header,
        )

        return token_refresh_struct.token_is_new

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
        use_auth_header: bool = False,
        refresh_token: str | None = None,
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
            )
            return ResultAddTokenHeader(token_added=True, token_is_new=token_is_fresh)
        else:
            LOG.warn(
                "URL is not approved: %s - Token will not be added to headers. Valid domains are: %s",
                url,
                valid_domains,
            )
            return ResultAddTokenHeader(token_added=False, token_is_new=False)


class IAPToolkit_OIDC(IAPToolkit):
    """
    OIDC-only implementation of IAPToolkit
    """

    _interface: OIDC

    def __init__(self, google_iap_client_id: str) -> None:
        super().__init__(google_iap_client_id)
        self._interface = OIDC(iap_client_id=google_iap_client_id)

    def get_token(
        self, refresh_token: str | None = None, bypass_cached: bool = False
    ) -> TokenRefreshStruct:
        try:
            return self._interface.get_token(
                iap_client_id=self._GOOGLE_IAP_CLIENT_ID, bypass_cached=bypass_cached
            )
        except ServiceAccountTokenException as ex:
            LOG.debug(ex)
            raise


class IAPToolkit_OAuth2(IAPToolkit):
    """
    OAuth2.0-only implementation of IAPToolkit
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
        self._interface = OAuth2(iap_client_id=google_iap_client_id, client_id=google_client_id)

    def get_refresh_token(
        self, auth_code: str, redirect_uri: str, bypass_cached: bool = False
    ) -> t.Any:

        # TODO: Cache
        # TODO: Expiry
        expired = True

        if expired or bypass_cached:
            refresh_token = self._interface.get_refresh_token_from_auth_code(
                client_id=self._GOOGLE_CLIENT_ID,
                client_secret=self._GOOGLE_CLIENT_SECRET,
                auth_code=auth_code,
                redirect_uri=redirect_uri,
            )

        # TODO: Expiry
        # TODO: Move this when implementing cache
        return TokenStructOAuth2(refresh_token=refresh_token, token_is_new=expired or bypass_cached)

    def get_token(self, refresh_token: str, bypass_cached: bool = False) -> TokenRefreshStruct:
        if not self._GOOGLE_CLIENT_ID or not self._GOOGLE_CLIENT_SECRET:
            raise ValueError()  # TODO

        # TODO: Get from cache and check expiry
        expired = True

        if expired or bypass_cached:
            token: str = self._interface.get_id_token_from_refresh_token(
                client_id=self._GOOGLE_CLIENT_ID,
                client_secret=self._GOOGLE_CLIENT_SECRET,
                refresh_token=refresh_token,
                iap_client_id=self._GOOGLE_IAP_CLIENT_ID,
            )

        # TODO: Move this when implementing cache
        return TokenRefreshStruct(id_token=token, token_is_new=expired or bypass_cached)

    def check_url_and_add_token_header(
        self,
        url: str | ParseResult,
        request_headers: dict,
        refresh_token: str,
        valid_domains: t.List[str] | None = None,
        use_auth_header: bool = False,
    ) -> ResultAddTokenHeader:
        return super().check_url_and_add_token_header(
            url=url,
            request_headers=request_headers,
            valid_domains=valid_domains,
            use_auth_header=use_auth_header,
            refresh_token=refresh_token,
        )
