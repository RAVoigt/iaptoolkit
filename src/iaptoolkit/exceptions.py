import os
import typing as t

from google.auth.environment_vars import CREDENTIALS as GOOGLE_CREDENTIALS_FILE_PATH
from google.auth.exceptions import DefaultCredentialsError
from google.auth.exceptions import RefreshError


class IAPToolkitBaseException(Exception):
    pass


class IAPBadResponse(IAPToolkitBaseException):
    pass


class InvalidDomain(IAPToolkitBaseException):
    pass


class TokenException(IAPToolkitBaseException):
    pass


class TokenStorageException(TokenException):
    pass


class GoogleTokenException(TokenException):
    """
    Wrapper for exceptions from Google's auth lib
    """
    def __init__(
        self, message: str, google_exception: t.Union[DefaultCredentialsError, RefreshError] | None
    ):
        self.google_exception = google_exception
        credentials_env_var_value = os.environ.get(GOOGLE_CREDENTIALS_FILE_PATH)
        metadata_server_attempted = not credentials_env_var_value
        self.message = (
            f"{message}, "
            f"metadata_attempted='{metadata_server_attempted}', "
            f"env_var='{GOOGLE_CREDENTIALS_FILE_PATH}', "
            f"env_var_value='{credentials_env_var_value or ''}', "
            f"google_exception='{str(google_exception)}'"
        )
        super().__init__(self.message)

    @property
    def retryable(self):
        return self.google_exception and self.google_exception._retryable

# SA / OIDC

class ServiceAccountTokenException(GoogleTokenException):
    pass


class ServiceAccountTokenFailedRefresh(ServiceAccountTokenException):
    pass


class ServiceAccountNoDefaultCredentials(ServiceAccountTokenException):
    pass

# OAuth2 / User

class OAuth2RefreshFromAuthCodeFailed(TokenException):
    pass


class OAuth2IDTokenFromRefreshFailed(TokenException):
    pass
