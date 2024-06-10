import datetime
import typing as t

from google.auth.compute_engine import IDTokenCredentials as GoogleIDTokenCredentials
from google.auth.exceptions import DefaultCredentialsError as GoogleDefaultCredentialsError
from google.auth.exceptions import RefreshError as GoogleRefreshError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token as google_id_token_lib

from kvcommon.logger import get_logger
from kvcommon.datastore.backend import DictBackend

from iaptoolkit.exceptions import ServiceAccountTokenException
from iaptoolkit.exceptions import ServiceAccountTokenFailedRefresh
from iaptoolkit.exceptions import ServiceAccountNoDefaultCredentials
from iaptoolkit.exceptions import TokenStorageException

from iaptoolkit.tokens.base import BaseTokenInterface
from iaptoolkit.tokens.structs import TokenStruct
from iaptoolkit.tokens.structs import TokenRefreshStruct

from .datastore_oidc import TokenDatastore_OIDC



LOG = get_logger("iaptk-oidc")
MAX_RECURSE = 3


class OIDC(BaseTokenInterface):
    """
    Base class for interacting with service accounts and OIDC tokens for IAP

    # TODO: Move Google-specific logic to GoogleServiceAccount
    """
    _datastore: TokenDatastore_OIDC

    def __init__(self, iap_client_id: str) -> None:
        super().__init__(
            datastore=TokenDatastore_OIDC(DictBackend),
            iap_client_id=iap_client_id,
        )

    def _store_token(self, id_token: str, token_expiry: datetime.datetime):
        self._datastore.store_token(self._iap_client_id, id_token, token_expiry)

    def _get_stored_token(self) -> dict | None:
        return self._datastore.get_stored_token(iap_client_id=self._iap_client_id)

    def get_stored_token(self) -> TokenStruct | None:
        return super().get_stored_token()

    # TODO: Unstatic
    @staticmethod
    def _get_fresh_credentials(iap_client_id: str) -> GoogleIDTokenCredentials:

        try:
            request = GoogleRequest()
            credentials: GoogleIDTokenCredentials = google_id_token_lib.fetch_id_token_credentials(
                iap_client_id, request
            )  # type: ignore
            credentials.refresh(request)

        except GoogleDefaultCredentialsError as ex:
            # The exceptions that google's libs raise in this case are somewhat vague; wrap them.
            raise ServiceAccountNoDefaultCredentials(
                message="Failed to get ServiceAccount token: Lacking default credentials.",
                google_exception=ex,
            )
        except GoogleRefreshError as ex:
            # Likely attempting to get a token for a service account in an environment that
            # doesn't have one attached.
            raise ServiceAccountTokenFailedRefresh(
                message="Failed to get ServiceAccount token: Refreshing token failed.",
                google_exception=ex,
            )
        return credentials

    # TODO: Unstatic
    @staticmethod
    def _get_fresh_token(iap_client_id: str) -> TokenStruct:
        google_credentials = OIDC._get_fresh_credentials(iap_client_id)
        id_token: str = str(google_credentials.token)

        # Google lib uses deprecated 'utcfromtimestamp' func as of v2.29.x
        # e.g.: datetime.datetime.utcfromtimestamp(payload["exp"])
        # This creates a TZ-naive datetime in UTC from a POSIX timestamp.
        # Python datetimes assume local TZ, and we want to explicitly only work in UTC here.
        token_expiry = google_credentials.expiry.replace(tzinfo=datetime.timezone.utc)

        return TokenStruct(id_token=id_token, expiry=token_expiry)

    # TODO: Unstatic
    def get_token(
        self, iap_client_id: str, bypass_cached: bool = False, attempts: int = 0
    ) -> TokenRefreshStruct:
        """Retrieves an OIDC token for the current environment either from environment variable or from
        metadata service.

        1. If the environment variable ``GOOGLE_APPLICATION_CREDENTIALS`` is set
        to the path of a valid service account JSON file, then ID token is
        acquired using this service account credentials.
        2. If the application is running in Compute Engine, App Engine or Cloud Run,
        then the ID token is obtained from the metadata server.

        Args:
            iap_client_id: The client ID used by IAP. Can be thought of as JWT audience.
            bypass_cached: Force retrieval of fresh tokens, bypassing in-memory cache
            attempts: For recursive retries

        Returns:
            A struct containing:
                id_token: An OIDC auth token for use in connecting through IAP
                token_is_new: A bool indicating if the refresh token is new (i.e.; the previous had expired)

        Raises:
            :class:`ServiceAccountTokenException` if a token could not be retrieved due to either
            missing credentials from env-var/JSON or inability to talk to metadata server.
        """

        use_cache = not bypass_cached

        try:
            token_from_cache = False
            token_struct = (use_cache and self.get_stored_token()) or None
            if use_cache and token_struct:
                token_from_cache = True
            else:
                token_struct = OIDC._get_fresh_token(iap_client_id)

            self._store_token(token_struct.id_token, token_struct.expiry)

            token_refresh_struct = TokenRefreshStruct(
                id_token=token_struct.id_token, token_is_new=not token_from_cache
            )
            return token_refresh_struct

        except ServiceAccountTokenException as ex:
            attempts += 1
            if attempts > MAX_RECURSE or not ex.retryable:
                raise
            return self.get_token(iap_client_id, bypass_cached=False, attempts=attempts)

        except TokenStorageException as ex:
            if attempts > 1:
                raise
            attempts += 1
            # Try again without involving the cache
            return self.get_token(iap_client_id, bypass_cached=True, attempts=attempts)
