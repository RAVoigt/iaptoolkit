import asyncio
import datetime
import json
import typing as t

import google.auth
import google.api_core.exceptions
from google.auth.compute_engine import IDTokenCredentials as GoogleIDTokenCredentials
from google.auth.exceptions import DefaultCredentialsError as GoogleDefaultCredentialsError
from google.auth.exceptions import RefreshError as GoogleRefreshError
from google.auth.transport.requests import Request as GoogleRequest
from google.cloud import iam_credentials_v1
from google.oauth2 import id_token as google_id_token_lib
from otel_extensions import instrumented

from kvcommon import logger
from iaptoolkit import exceptions
from iaptoolkit.tokens.token_datastore import datastore

from .structs import TokenStruct


LOG = logger.get_logger("iaptk")
MAX_RECURSE = 3


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.UTC)


def _fix_token_tz(token_expiry: datetime.datetime):
        # Google lib uses deprecated 'utcfromtimestamp' func as of v2.29.x
        # e.g.: datetime.datetime.utcfromtimestamp(payload["exp"])
        # This creates a TZ-naive datetime in UTC from a POSIX timestamp.
        # Python datetimes assume local TZ, and we want to explicitly only work in UTC here.
        # TODO: Check if this is still necessary
        return token_expiry.replace(tzinfo=datetime.timezone.utc)


class ServiceAccount(object):
    """Base class for interacting with service accounts and OIDC tokens for IAP"""

    # TODO: This is a static namespace for SA functions. Turn it into a per-iap-audience client
    # TODO: Move Google-specific logic to GoogleServiceAccount

    # ==== ==== ==== ====
    # Datastore/Cache

    @staticmethod
    @instrumented
    def _store_token(iap_audience: str, id_token: str, token_expiry: datetime.datetime):
        try:
            datastore.store_service_account_token(iap_audience, id_token, token_expiry)
        except Exception as ex:  # Err on the side of not letting token-caching break requests.
            raise exceptions.TokenStorageException(f"Exception when trying to store token. exception={ex}")

    @staticmethod
    @instrumented
    def _store_jwt(service_account_email: str, url_audience: str, signed_jwt: str, expiry: datetime.datetime):
        try:
            datastore.store_service_account_jwt(
                service_account_email=service_account_email,
                url_audience=url_audience,
                signed_jwt=signed_jwt,
                expiry=expiry,
            )
        except Exception as ex:  # Err on the side of not letting token-caching break requests.
            raise exceptions.TokenStorageException(f"Exception when trying to store token. exception={ex}")

    @staticmethod
    @instrumented
    def get_stored_token(iap_audience: str) -> TokenStruct | None:
        try:
            return datastore.get_stored_service_account_token(iap_audience)

        except Exception as ex:
            # Err on the side of not letting token-caching break requests, hence blanket except
            raise exceptions.TokenStorageException(f"Exception when trying to retrieve stored token. exception={ex}")

    @staticmethod
    @instrumented
    def get_stored_jwt(service_account_email: str, url_audience: str) -> TokenStruct | None:
        try:
            return datastore.get_stored_service_account_jwt(
                service_account_email=service_account_email, url_audience=url_audience
            )

        except Exception as ex:
            # Err on the side of not letting token-caching break requests, hence blanket except
            raise exceptions.TokenStorageException(f"Exception when trying to retrieve stored token. exception={ex}")

    # ==== ==== ==== ====
    # Credentials

    @staticmethod
    @instrumented
    def _get_fresh_credentials(iap_audience: str) -> GoogleIDTokenCredentials:

        try:
            request = GoogleRequest()
            credentials: GoogleIDTokenCredentials = google_id_token_lib.fetch_id_token_credentials(
                iap_audience, request
            )  # type: ignore
            credentials.refresh(request)

        except GoogleDefaultCredentialsError as ex:
            # The exceptions that google's libs raise in this case are somewhat vague; wrap them.
            raise exceptions.ServiceAccountNoDefaultCredentials(
                message="Failed to get ServiceAccount token: Lacking default credentials.",
                google_exception=ex,
            )
        except GoogleRefreshError as ex:
            # Likely attempting to get a token for a service account in an environment that
            # doesn't have one attached.
            raise exceptions.ServiceAccountTokenFailedRefresh(
                message="Failed to get ServiceAccount token: Refreshing token failed.",
                google_exception=ex,
            )
        return credentials

    # @staticmethod
    # async def _get_fresh_credentials_async(iap_audience: str) -> GoogleIDTokenCredentials:
    #     # TODO: async-native way to get these credentials
    #     return await asyncio.to_thread(ServiceAccount._get_fresh_credentials, iap_audience)


    # ==== ==== ==== ====
    # Token

    @staticmethod
    @instrumented
    def _get_token_from_google_credentials(google_credentials: GoogleIDTokenCredentials) -> str:
        id_token: str = str(google_credentials.token) # Note: This makes network calls to metadata server under the hood - NOT async safe
        if not id_token:
            raise exceptions.TokenException("Invalid [empty] token retrieved for Service Account.")
        return id_token

    # @staticmethod
    # async def _get_token_from_google_credentials_async(google_credentials: GoogleIDTokenCredentials) -> str:
    #     # TODO: async-native way to get this token
    #     return await asyncio.to_thread(ServiceAccount._get_token_from_google_credentials, google_credentials)

    @staticmethod
    @instrumented
    def _get_fresh_token(iap_audience: str, use_jwt: bool = False) -> TokenStruct:
        google_credentials = ServiceAccount._get_fresh_credentials(iap_audience)
        id_token: str = ServiceAccount._get_token_from_google_credentials(google_credentials)

        token_expiry = _fix_token_tz(google_credentials.expiry)
        return TokenStruct(id_token=id_token, expiry=token_expiry, from_cache=False)

    # @staticmethod
    # async def _get_fresh_token_async(iap_audience: str, use_jwt: bool = False) -> TokenStruct:
    #     google_credentials = await ServiceAccount._get_fresh_credentials_async(iap_audience)
    #     id_token: str = await ServiceAccount._get_token_from_google_credentials_async(google_credentials)

    #     token_expiry = _fix_token_tz(google_credentials.expiry)
    #     return TokenStruct(id_token=id_token, expiry=token_expiry, from_cache=False)

    # ==== ==== ==== ====
    # JWT

    @staticmethod
    @instrumented
    def _get_jwt(service_account_email: str, url_audience: str) -> TokenStruct:
        """
        Returns a signed JWT for the specified service account
        """
        now = _utcnow()
        expiration_delta = datetime.timedelta(seconds=3595)
        expiry_dt = now + expiration_delta

        issued_at = int(now.timestamp())
        expiry = int(expiry_dt.timestamp())

        jwt_payload = {
            "iss": service_account_email,
            "sub": service_account_email,
            "aud": url_audience,
            "iat": issued_at,
            "exp": expiry,
        }
        jwt_payload_str = json.dumps(jwt_payload)

        source_credentials, project_id = google.auth.default()
        iam_client = iam_credentials_v1.IAMCredentialsClient(credentials=source_credentials)  # type: ignore
        name = iam_client.service_account_path("-", service_account_email)
        response = iam_client.sign_jwt(name=name, payload=jwt_payload_str)
        return TokenStruct.for_jwt(signed_jwt=response.signed_jwt, expiry=expiry_dt, from_cache=False)

    @staticmethod
    async def _get_jwt_async(service_account_email: str, url_audience: str) -> TokenStruct:
        """
        See _get_jwt()
        # TODO: async-native way to get this
        """
        return await asyncio.to_thread(ServiceAccount._get_jwt, service_account_email, url_audience)

    @staticmethod
    @instrumented
    def get_jwt(
        service_account_email: str, url_audience: str, bypass_cached: bool = False, attempts: int = 0
    ) -> TokenStruct:
        use_cache = not bypass_cached

        try:
            token_struct: TokenStruct | None = None

            if use_cache:
                token_struct = ServiceAccount.get_stored_jwt(
                    service_account_email=service_account_email, url_audience=url_audience
                )

            if not token_struct:
                token_struct = ServiceAccount._get_jwt(
                    service_account_email=service_account_email, url_audience=url_audience
                )
                if use_cache:
                    ServiceAccount._store_jwt(
                        service_account_email=service_account_email,
                        url_audience=url_audience,
                        signed_jwt=token_struct.id_token,
                        expiry=token_struct.expiry,
                    )

            return token_struct

        except google.api_core.exceptions.PermissionDenied as ex:
            raise exceptions.JWTPermissionException(
                "Permission denied while retrieving signed JWT for service account. "
                "Service Account requires IAM Role: 'roles/iam.serviceAccountTokenCreator'",
                google_exception=ex,
            )

        except exceptions.ServiceAccountTokenException as ex:
            attempts += 1
            if attempts > MAX_RECURSE or not ex.retryable:
                raise
            return ServiceAccount.get_jwt(
                service_account_email=service_account_email,
                url_audience=url_audience,
                bypass_cached=False,
                attempts=attempts,
            )

        except exceptions.TokenStorageException as ex:
            if attempts > 1:
                raise
            attempts += 1
            # Try again without involving the cache
            return ServiceAccount.get_jwt(
                service_account_email=service_account_email,
                url_audience=url_audience,
                bypass_cached=True,
                attempts=attempts,
            )

    @staticmethod
    async def get_jwt_async(
        service_account_email: str, url_audience: str, bypass_cached: bool = False, attempts: int = 0
    ) -> TokenStruct:
        return await asyncio.to_thread(ServiceAccount.get_jwt, service_account_email, url_audience, bypass_cached, attempts)

    @staticmethod
    @instrumented
    def get_token(iap_audience: str, bypass_cached: bool = False, _attempts: int = 0) -> TokenStruct:
        """Retrieves an OIDC token for the current environment using credentials either from
        environment variable or from metadata service.

        1. If the environment variable ``GOOGLE_APPLICATION_CREDENTIALS`` is set
        to the path of a valid service account JSON file, then ID token is
        acquired using this service account credentials.
        2. If the application is running in Compute Engine, App Engine or Cloud Run,
        then the ID token is obtained from the metadata server.

        Args:
            iap_audience: The client ID used by IAP. Can be thought of as JWT audience.
            bypass_cached: If true, create a new token; don't retrieve from storage

        Returns:
            An OIDC token for use in connecting through IAP.

        Raises:
            :class:`ServiceAccountTokenException` if a token could not be retrieved due to either
            missing credentials from env-var/JSON or inability to talk to metadata server.
        """

        use_cache = not bypass_cached

        try:
            token_struct: TokenStruct | None = None

            if use_cache:
                token_struct = ServiceAccount.get_stored_token(iap_audience)

            if not token_struct:
                token_struct = ServiceAccount._get_fresh_token(iap_audience)
                if use_cache:
                    ServiceAccount._store_token(iap_audience, token_struct.id_token, token_struct.expiry)

            return token_struct

        except exceptions.ServiceAccountTokenException as ex:
            _attempts += 1
            if _attempts > MAX_RECURSE or not ex.retryable:
                raise
            return ServiceAccount.get_token(iap_audience, bypass_cached=False, _attempts=_attempts)

        except exceptions.TokenStorageException as ex:
            if _attempts > 1:
                raise
            _attempts += 1
            # Try again without involving the cache
            return ServiceAccount.get_token(iap_audience, bypass_cached=True, _attempts=_attempts)

    # @staticmethod
    # async def get_token_async(iap_audience: str, bypass_cached: bool = False, _attempts: int = 0) -> TokenStruct:
    #     """
    #     See get_token()
    #     """

    #     use_cache = not bypass_cached

    #     try:
    #         token_struct: TokenStruct | None = None

    #         if use_cache:
    #             token_struct = ServiceAccount.get_stored_token(iap_audience)

    #         if not token_struct:
    #             token_struct = await ServiceAccount._get_fresh_token_async(iap_audience)
    #             if use_cache:
    #                 ServiceAccount._store_token(iap_audience, token_struct.id_token, token_struct.expiry)

    #         return token_struct

    #     except exceptions.ServiceAccountTokenException as ex:
    #         _attempts += 1
    #         if _attempts > MAX_RECURSE or not ex.retryable:
    #             raise
    #         return await ServiceAccount.get_token_async(iap_audience, bypass_cached=False, _attempts=_attempts)

    #     except exceptions.TokenStorageException as ex:
    #         if _attempts > 1:
    #             raise
    #         _attempts += 1
    #         # Try again without involving the cache
    #         return await ServiceAccount.get_token_async(iap_audience, bypass_cached=True, _attempts=_attempts)


class GoogleServiceAccount(ServiceAccount):
    """
    For interacting with Google service accounts, Service Account JWTs and OIDC tokens for Google IAP

    Service Account requires IAM Role: 'roles/iam.serviceAccountTokenCreator'
    """

    def __init__(self, service_account_email: str) -> None:
        if not service_account_email or not isinstance(service_account_email, str):
            raise exceptions.ServiceAccountTokenException(
                "Invalid iap_audience for GoogleServiceAccount", google_exception=None
            )
        self._service_account_email = service_account_email
        super().__init__()

    @instrumented
    def get_stored_jwt(self, url_audience: str) -> t.Optional[TokenStruct]:
        return ServiceAccount.get_stored_jwt(self._service_account_email, url_audience=url_audience)

    @instrumented
    def get_jwt(self, url_audience: str, bypass_cached: bool = False, attempts: int = 0) -> TokenStruct:
        return ServiceAccount.get_jwt(
            service_account_email=self._service_account_email,
            url_audience=url_audience,
            bypass_cached=bypass_cached,
            attempts=attempts,
        )

    # async def get_jwt_async(self, url_audience: str, bypass_cached: bool = False, attempts: int = 0) -> TokenStruct:
    #     return await ServiceAccount.get_jwt_async(
    #         service_account_email=self._service_account_email,
    #         url_audience=url_audience,
    #         bypass_cached=bypass_cached,
    #         attempts=attempts,
    #     )
