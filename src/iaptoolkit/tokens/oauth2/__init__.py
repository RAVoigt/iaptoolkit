import datetime
import json
import typing as t
import requests

from kvcommon import logger

from iaptoolkit.tokens.base import BaseTokenInterface
from iaptoolkit.tokens.structs import TokenStruct
from iaptoolkit.exceptions import OAuth2IDTokenFromRefreshFailed
from iaptoolkit.exceptions import OAuth2RefreshFromAuthCodeFailed

from .datastore_oauth2 import TokenDatastore_OAuth2


LOG = logger.get_logger("iaptk-oauth2")

GOOGLE_OAUTH_TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"


def get_localhost_redirect_uri(listen_port: int):
    return f"http://localhost:{listen_port}"


def get_oauth2_auth_url(client_id: str, redirect_uri: str):
    # TODO: Unhardcode
    return (
        f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}"
        f"&response_type=code&scope=openid%20email&access_type=offline&redirect_uri={redirect_uri}"
    )


class OAuth2(BaseTokenInterface):
    """
    Base class for interacting with OAuth2.0 tokens for IAP

    OAuth2.0 access Tokens have a shorter expiry (<60mins)
    Refresh tokens have a longer expiry and are used to retrieve new access tokens

    TODO: Move Google-specific logic to GoogleServiceAccount
    """

    _datastore: TokenDatastore_OAuth2
    _client_id: str
    _client_secret: str

    def __init__(
        self,
        iap_client_id: str,
        client_id: str,
        client_secret: str,
        validate_iap_client_id: bool = False,
    ) -> None:
        super().__init__(
            datastore=TokenDatastore_OAuth2(storage_dir_path="~/.iaptoolkit", filename="iaptoolkit.conf"),
            iap_client_id=iap_client_id,
            validate_iap_client_id=validate_iap_client_id,
        )
        self._client_id = client_id
        self._client_secret = client_secret

    def _store_token(self, id_token: str, token_expiry: datetime.datetime):
        self._datastore.store_token(
            iap_client_id=self._iap_client_id,
            client_id=self._client_id,
            id_token=id_token,
            token_expiry=token_expiry,
        )

    def _store_refresh_token(self, refresh_token: str, token_expiry: datetime.datetime):
        self._datastore.store_refresh_token(
            iap_client_id=self._iap_client_id,
            client_id=self._client_id,
            refresh_token=refresh_token,
            token_expiry=token_expiry,
        )

    def _get_stored_token(self) -> TokenStruct | None:
        return self._datastore.get_stored_token(iap_client_id=self._iap_client_id, client_id=self._client_id)

    def get_stored_token(self) -> TokenStruct | None:
        return self._get_stored_token()

    def get_stored_refresh_token(self) -> TokenStruct | None:
        return self._datastore.get_stored_refresh_token(iap_client_id=self._iap_client_id, client_id=self._client_id)

    def get_id_token_from_refresh_token(self, refresh_token: str) -> TokenStruct:
        oauth2_token_url = GOOGLE_OAUTH_TOKEN_URL  # TODO: Unhardcode
        request_payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "audience": self._iap_client_id,
        }
        response = requests.post(oauth2_token_url, data=request_payload)
        response_dict = json.loads(response.text)

        id_token: str = response_dict.get("id_token", None)
        if response.status_code != 200 or not id_token:
            raise OAuth2IDTokenFromRefreshFailed(
                f"Failure in acquiring OAuth2.0 access token from refresh token - HTTP Response:"
                f"{response.status_code} : {response.reason or 'Unknown'} : {response.text or ''}"
            )

        token_expiry_seconds: int = int(response_dict.get("expires_in", 3599))
        token_expiry = datetime.datetime.now() + datetime.timedelta(seconds=token_expiry_seconds)
        token_expiry.replace(tzinfo=datetime.timezone.utc)
        self._store_token(id_token=id_token, token_expiry=token_expiry)
        return TokenStruct(id_token=id_token, expiry=token_expiry, from_cache=False)

    def get_refresh_token_from_auth_code(self, auth_code: str, redirect_uri: str) -> TokenStruct:
        oauth2_token_url = GOOGLE_OAUTH_TOKEN_URL  # TODO: Unhardcode, subclass
        request_payload = {
            "code": auth_code,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        response = requests.post(oauth2_token_url, data=request_payload)
        response_dict = json.loads(response.text)
        refresh_token: str = response_dict.get("refresh_token", None)
        token_expiry_days: int = int(response_dict.get("expires_in", 3599))

        if response.status_code != 200 or not refresh_token:
            raise OAuth2RefreshFromAuthCodeFailed(
                f"Failure in acquiring refresh token from auth code - HTTP Response:"
                f"{response.status_code} : {response.reason or 'Unknown'} : {response.text or ''}"
            )
        token_expiry = datetime.datetime.now() + datetime.timedelta(days=token_expiry_days)
        token_expiry.replace(tzinfo=datetime.timezone.utc)
        self._store_refresh_token(refresh_token=refresh_token, token_expiry=token_expiry)
        return TokenStruct(id_token=refresh_token, expiry=token_expiry, from_cache=False)
