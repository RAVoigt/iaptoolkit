import datetime
import json
import typing as t
import requests

from kvcommon import logger
from kvcommon.datastore.backend import DictBackend

from iaptoolkit.tokens.base import BaseTokenInterface
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

    # TODO: Move Google-specific logic to GoogleServiceAccount
    """

    _datastore: TokenDatastore_OAuth2
    _client_id: str

    def __init__(self, iap_client_id: str, client_id: str) -> None:
        super().__init__(
            datastore=TokenDatastore_OAuth2(DictBackend),
            iap_client_id=iap_client_id,
        )
        self._client_id = client_id

    def _store_token(self, id_token: str, token_expiry: datetime.datetime):
        self._datastore.store_token(self._iap_client_id, self._client_id, id_token, token_expiry)

    def _get_stored_token(self, iap_client_id: str, client_id: str) -> dict | None:
        return self._datastore.get_stored_token(iap_client_id=iap_client_id, client_id=client_id)

    # TODO: Unstatic
    @staticmethod
    def get_id_token_from_refresh_token(
        client_id: str,
        client_secret: str,
        refresh_token: str,
        iap_client_id: str,
    ) -> str:

        oauth2_token_url = GOOGLE_OAUTH_TOKEN_URL  # TODO: Unhardcode
        request_payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "audience": iap_client_id,
        }
        response = requests.post(oauth2_token_url, data=request_payload)
        response_dict = json.loads(response.text)
        id_token: str = response_dict.get("id_token", None)
        if response.status_code != 200 or not id_token:
            raise OAuth2IDTokenFromRefreshFailed(
                f"Failure in acquiring OAuth2.0 access token from refresh token - HTTP Response:"
                f"{response.status_code} : {response.reason or 'Unknown'} : {response.text or ''}"
            )
        return id_token

    # TODO: Unstatic
    @staticmethod
    def get_refresh_token_from_auth_code(
        client_id: str,
        client_secret: str,
        auth_code: str,
        redirect_uri: str,
    ) -> str:
        oauth2_token_url = GOOGLE_OAUTH_TOKEN_URL  # TODO: Unhardcode
        request_payload = {
            "code": auth_code,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        response = requests.post(oauth2_token_url, data=request_payload)
        response_dict = json.loads(response.text)
        refresh_token: str = response_dict.get("refresh_token", None)
        if response.status_code != 200 or not refresh_token:
            raise OAuth2RefreshFromAuthCodeFailed(
                f"Failure in acquiring refresh token from auth code - HTTP Response:"
                f"{response.status_code} : {response.reason or 'Unknown'} : {response.text or ''}"
            )
        return refresh_token
