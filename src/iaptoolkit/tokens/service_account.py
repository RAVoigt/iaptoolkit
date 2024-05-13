import datetime
import typing as t

from google.auth.compute_engine import IDTokenCredentials as GoogleIDTokenCredentials
from google.auth.exceptions import DefaultCredentialsError as GoogleDefaultCredentialsError
from google.auth.exceptions import RefreshError as GoogleRefreshError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token as google_id_token_lib

from kvcommon import logger

# TODO: Don't hardcode the association between OIDC/SA and dict-datastore
from iaptoolkit.tokens.token_datastore import datastore
from iaptoolkit.exceptions import ServiceAccountTokenException
from iaptoolkit.exceptions import ServiceAccountTokenFailedRefresh
from iaptoolkit.exceptions import ServiceAccountNoDefaultCredentials
from iaptoolkit.exceptions import TokenStorageException

from .structs import TokenStruct
from .structs import TokenRefreshStruct


LOG = logger.get_logger("iaptk")
MAX_RECURSE = 3


class ServiceAccount(object):
    """Base class for interacting with service accounts and OIDC tokens for IAP"""

    # TODO: This is a static namespace for SA functions. Turn it into a per-iap-client-id client
    # TODO: Move Google-specific logic to GoogleServiceAccount

    @staticmethod
    def _store_token(iap_client_id: str, id_token: str, token_expiry: datetime.datetime):
        try:
            datastore.store_service_account_token(iap_client_id, id_token, token_expiry)
        except Exception as ex:  # Err on the side of not letting token-caching break requests.
            raise TokenStorageException(f"Exception when trying to store token. exception={ex}")

    @staticmethod
    def get_stored_token(iap_client_id: str) -> t.Optional[TokenStruct]:
        try:
            token_dict = datastore.get_stored_service_account_token(iap_client_id)
            if (
                not token_dict
                or not token_dict.get("id_token", None)
                or not token_dict.get("token_expiry", None)
            ):
                LOG.debug("No stored service account token for current iap_client_id")
                return

            id_token_from_dict = token_dict.get("id_token")
            token_expiry_from_dict = token_dict.get("token_expiry", "")

            if not id_token_from_dict:
                LOG.warning("Invalid stored ID token")
                return

            token_expiry = ""
            try:
                token_expiry = datetime.datetime.fromisoformat(token_expiry_from_dict)
            except (ValueError, TypeError) as ex:
                LOG.debug("Invalid token expiry for current iap_client_id")
                return

            token_struct = TokenStruct(id_token=id_token_from_dict, expiry=token_expiry)
            if token_struct.expired:
                LOG.debug("Stored service account token for current iap_client_id has EXPIRED")
                return
            return token_struct

        except Exception as ex:
            # Err on the side of not letting token-caching break requests, hence blanket except
            raise TokenStorageException(
                f"Exception when trying to retrieve stored token. exception={ex}"
            )

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

    @staticmethod
    def _get_fresh_token(iap_client_id: str) -> TokenStruct:
        google_credentials = ServiceAccount._get_fresh_credentials(iap_client_id)
        id_token: str = str(google_credentials.token)

        # Google lib uses deprecated 'utcfromtimestamp' func as of v2.29.x
        # e.g.: datetime.datetime.utcfromtimestamp(payload["exp"])
        # This creates a TZ-naive datetime in UTC from a POSIX timestamp.
        # Python datetimes assume local TZ, and we want to explicitly only work in UTC here.
        token_expiry = google_credentials.expiry.replace(tzinfo=datetime.timezone.utc)

        return TokenStruct(id_token=id_token, expiry=token_expiry)

    @staticmethod
    def get_token(
        iap_client_id: str, bypass_cached: bool = False, attempts: int = 0
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

        Returns:
            An OIDC token for use in connecting through IAP.

        Raises:
            :class:`ServiceAccountTokenException` if a token could not be retrieved due to either
            missing credentials from env-var/JSON or inability to talk to metadata server.
        """

        use_cache = not bypass_cached

        try:
            token_from_cache = False
            token_struct = (use_cache and ServiceAccount.get_stored_token(iap_client_id)) or None
            if use_cache and token_struct:
                token_from_cache = True
            else:
                token_struct = ServiceAccount._get_fresh_token(iap_client_id)

            ServiceAccount._store_token(iap_client_id, token_struct.id_token, token_struct.expiry)

            token_refresh_struct = TokenRefreshStruct(
                id_token=token_struct.id_token, token_is_new=not token_from_cache
            )
            return token_refresh_struct

        except ServiceAccountTokenException as ex:
            attempts += 1
            if attempts > MAX_RECURSE or not ex.retryable:
                raise
            return ServiceAccount.get_token(iap_client_id, bypass_cached=False, attempts=attempts)

        except TokenStorageException as ex:
            if attempts > 1:
                raise
            attempts += 1
            # Try again without involving the cache
            return ServiceAccount.get_token(iap_client_id, bypass_cached=True, attempts=attempts)


class GoogleServiceAccount(ServiceAccount):
    """For interacting with Google service accounts and OIDC tokens for Google IAP"""

    def __init__(self, iap_client_id: str) -> None:
        if not iap_client_id or not isinstance(iap_client_id, str):
            raise ServiceAccountTokenException(
                "Invalid iap_client_id for GoogleServiceAccount", google_exception=None
            )
        self._iap_client_id = iap_client_id
        super().__init__()

    def get_stored_token(self) -> t.Optional[TokenStruct]:
        return ServiceAccount.get_stored_token(self._iap_client_id)

    def get_token(self, bypass_cached: bool = False, attempts: int = 0) -> TokenRefreshStruct:
        return ServiceAccount.get_token(
            iap_client_id=self._iap_client_id, bypass_cached=bypass_cached, attempts=attempts
        )
