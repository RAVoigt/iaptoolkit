from __future__ import annotations

import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())

import typing as t
from urllib.parse import ParseResult
from urllib.parse import urlparse

from kvcommon import logger

from iaptoolkit import headers
from iaptoolkit.exceptions import ServiceAccountTokenException
from iaptoolkit.tokens.service_account import ServiceAccount
from iaptoolkit.tokens.structs import ResultAddTokenHeader

from iaptoolkit.tokens.structs import TokenRefreshStruct
from iaptoolkit.utils.urls import is_url_safe_for_token

LOG = logger.get_logger("iaptk")


class IAPToolkit:
    """
    Class to encapsulate client-specific vars and forward them to static functions
    """

    _GOOGLE_IAP_CLIENT_ID: str

    def __init__(
        self,
        google_iap_client_id: str,
    ) -> None:
        self._GOOGLE_IAP_CLIENT_ID = google_iap_client_id

    @staticmethod
    def sanitize_request_headers(request_headers: dict) -> dict:
        return headers.sanitize_request_headers(request_headers)

    def get_token_oidc(self, bypass_cached: bool = False) -> TokenRefreshStruct:
        try:
            return ServiceAccount.get_token(
                iap_client_id=self._GOOGLE_IAP_CLIENT_ID, bypass_cached=bypass_cached
            )
        except ServiceAccountTokenException as ex:
            LOG.debug(ex)
            raise

    def get_token_oidc_str(self, bypass_cached: bool = False) -> str:
        struct = self.get_token_oidc(bypass_cached=bypass_cached)
        return struct.id_token

    def get_token_oauth2(self, bypass_cached: bool = False) -> TokenRefreshStruct:
        # TODO
        raise NotImplementedError()

    def get_token_oauth2_str(self, bypass_cached: bool = False) -> str:
        struct = self.get_token_oauth2(bypass_cached=bypass_cached)
        return struct.id_token

    def get_token_and_add_to_headers(
        self, request_headers: dict, use_oauth2: bool = False, use_auth_header: bool = False
    ) -> bool:
        """
        Retrieves an auth token and inserts it into the supplied request_headers dict.
        request_headers is modified in-place

        Params:
            request_headers: dict of headers to insert into
            use_oauth2: Use OAuth2.0 credentials and respective token, else use OIDC (default)
                As a general guideline, OIDC is the assumed default approach for ServiceAccounts.
            use_auth_header: If true, use the 'Authorization' header instead of 'Proxy-Authorization'


        """
        if not use_oauth2:
            token_refresh_struct: TokenRefreshStruct = self.get_token_oidc()
        else:
            token_refresh_struct: TokenRefreshStruct = self.get_token_oauth2()

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
        use_oauth2: bool = False,
        use_auth_header: bool = False,
    ) -> ResultAddTokenHeader:
        """
        Checks that the supplied URL is valid (i.e.; in valid_domains) and if so, retrieves a
        token and adds it to request_headers.

        i.e.; A convenience wrapper with logging for is_url_safe_for_token() and get_token_and_add_to_headers()

        Params:
            url: URL string or urllib.ParseResult to check for validity
            request_headers: Dict of headers to insert into
            valid_domains: List of domains to validate URL against
            use_oauth2: Passed to get_token_and_add_to_headers() to determine if OAuth2.0 is used or OIDC (default)
        """

        if self.is_url_safe_for_token(url=url, valid_domains=valid_domains):
            token_is_fresh = self.get_token_and_add_to_headers(
                request_headers=request_headers,
                use_oauth2=use_oauth2,
                use_auth_header=use_auth_header,
            )
            return ResultAddTokenHeader(token_added=True, token_is_fresh=token_is_fresh)
        else:
            LOG.warn(
                "URL is not approved: %s - Token will not be added to headers. Valid domains are: %s",
                url,
                valid_domains,
            )
            return ResultAddTokenHeader(token_added=False, token_is_fresh=False)


class IAPToolkit_OIDC(IAPToolkit):
    """
    Convenience subclass of IAPToolkit for scenarios where OIDC will always be used, never OAuth2
    """

    def get_token_oauth2(self, *args, **kwargs):
        raise NotImplementedError("Cannot call OAuth2 methods on OIDC-only instance of IAPToolkit.")

    def get_token_oauth2_str(self, *args, **kwargs):
        raise NotImplementedError("Cannot call OAuth2 methods on OIDC-only instance of IAPToolkit.")

    def get_token_and_add_to_headers(
        self, request_headers: dict, use_auth_header: bool = False, use_oauth2: bool = False,
    ) -> bool:
        return super().get_token_and_add_to_headers(
            request_headers=request_headers, use_oauth2=use_oauth2, use_auth_header=use_auth_header
        )

    def check_url_and_add_token_header(
        self,
        url: str | ParseResult,
        request_headers: dict,
        valid_domains: t.List[str] | None = None,
        use_auth_header: bool = False,
    ) -> ResultAddTokenHeader:
        return super().check_url_and_add_token_header(
            url,
            request_headers=request_headers,
            valid_domains=valid_domains,
            use_oauth2=False,
            use_auth_header=use_auth_header,
        )


class IAPToolkit_OAuth2(IAPToolkit):
    """
    Convenience subclass of IAPToolkit for scenarios where OAuth2 will always be used, never OIDC
    """

    _GOOGLE_CLIENT_ID: str
    _GOOGLE_CLIENT_SECRET: str

    def __init__(
        self,
        google_iap_client_id: str,
        google_client_id: str,
        google_client_secret: str,
    ) -> None:
        super().__init__(google_iap_client_id=google_iap_client_id)
        self._GOOGLE_CLIENT_ID = google_client_id
        self._GOOGLE_CLIENT_SECRET = google_client_secret

    def get_token_oidc(self, *args, **kwargs):
        raise NotImplementedError("Cannot call OIDC methods on OAuth2-only instance of IAPToolkit.")

    def get_token_oidc_str(self, *args, **kwargs):
        raise NotImplementedError("Cannot call OIDC methods on OAuth2-only instance of IAPToolkit.")

    def get_token_and_add_to_headers(
        self, request_headers: dict, use_auth_header: bool = False, use_oauth2: bool = True,
    ) -> bool:
        return super().get_token_and_add_to_headers(
            request_headers=request_headers, use_oauth2=use_oauth2, use_auth_header=use_auth_header
        )

    def check_url_and_add_token_header(
        self,
        url: str | ParseResult,
        request_headers: dict,
        valid_domains: t.List[str] | None = None,
        use_auth_header: bool = False,
    ) -> ResultAddTokenHeader:
        return super().check_url_and_add_token_header(
            url=url,
            request_headers=request_headers,
            valid_domains=valid_domains,
            use_oauth2=True,
            use_auth_header=use_auth_header,
        )
