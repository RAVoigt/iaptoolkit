import datetime
import typing as t

from kvcommon import logger
from kvcommon.datastore.backend import DatastoreBackend
from kvcommon.datastore.backend import DictBackend

from kvcommon.datastore import VersionedDatastore

from iaptoolkit.exceptions import TokenStorageException
from iaptoolkit.constants import IAPTOOLKIT_CONFIG_VERSION

from .structs import TokenStruct


LOG = logger.get_logger("iaptk-ds")


class TokenDatastore(VersionedDatastore):
    _service_account_jwts_email_limit = 1000

    def __init__(self, backend: DatastoreBackend | type[DatastoreBackend]) -> None:
        super().__init__(backend=backend, config_version=IAPTOOLKIT_CONFIG_VERSION)
        self._ensure_tokens_dict()

    def _ensure_tokens_dict(self):
        tokens_dict = self.get_or_create_nested_dict("tokens")
        if "refresh" not in tokens_dict.keys():
            tokens_dict["refresh"] = None
        self.set_value("tokens", tokens_dict)

    @property
    def service_account_tokens(self) -> dict:
        return self.get_or_create_nested_dict("service_account_tokens")

    @property
    def service_account_jwts(self) -> dict:
        return self.get_or_create_nested_dict("service_account_jwts")

    def discard_existing_tokens(self):
        LOG.debug("Discarding existing tokens.")
        self.update_data(tokens={})

    def get_stored_service_account_token(self, iap_client_id: str) -> TokenStruct | None:
        token_data = self.service_account_tokens.get(iap_client_id, None)
        if not token_data or not token_data.id_token or not token_data.expiry:
            LOG.debug("No stored service account token for current iap_client_id")
            return
        return self._dict_to_tokenstruct(token_data)

    def store_service_account_token(self, iap_client_id: str, id_token: str, token_expiry: datetime.datetime):
        if not id_token:
            raise TokenStorageException("TokenDatastore: Attempting to store invalid [empty] token")

        tokens_dict = self.service_account_tokens
        self.service_account_tokens[iap_client_id] = dict(id_token=id_token, token_expiry=token_expiry.isoformat())

        try:
            self.update_data(service_account_tokens=tokens_dict)
        except Exception as ex:
            LOG.error("Failed to store service account token for re-use. exception=%s", ex)

    def _get_or_create_dict_for_service_account_and_url(self, service_account_email: str, url_audience: str):
        jwts_dict = self.service_account_jwts
        jwts_dict_for_email = jwts_dict.get(service_account_email, dict())
        jwts_dict[service_account_email] = jwts_dict_for_email

        token_dict = jwts_dict_for_email.get(url_audience, dict())
        return token_dict

    def get_stored_service_account_jwt(self, service_account_email: str, url_audience: str) -> TokenStruct | None:
        jwts_dict_for_email = self._get_or_create_dict_for_service_account_and_url(service_account_email, url_audience)
        token_data = jwts_dict_for_email.get(url_audience, None)
        if not token_data:
            LOG.debug("No stored service account JWT for service account '%s'", service_account_email)
            return
        return self._dict_to_tokenstruct(token_data, is_jwt=True)

    def store_service_account_jwt(
        self, service_account_email: str, url_audience: str, signed_jwt: str, expiry: datetime.datetime
    ):
        if not signed_jwt:
            raise TokenStorageException("TokenDatastore: Attempting to store invalid [empty] jwt")

        try:
            token_dict = self._get_or_create_dict_for_service_account_and_url(service_account_email, url_audience)
            token_dict["signed_jwt"] = signed_jwt
            token_dict["token_expiry"] = expiry.isoformat()
        except Exception as ex:
            LOG.error("Failed to store service account JWT for re-use. exception=%s", ex)

    @staticmethod
    def _dict_to_tokenstruct(token_data: dict, is_jwt: bool = False) -> TokenStruct | None:
        if not token_data:
            return

        id_token_from_dict: str = token_data.get("id_token", "")
        token_expiry_from_dict: str = token_data.get("token_expiry", "")
        if not id_token_from_dict or not token_expiry_from_dict:
            return

        token_expiry = ""
        try:
            token_expiry = datetime.datetime.fromisoformat(token_expiry_from_dict)
        except (ValueError, TypeError) as ex:
            LOG.warning("Invalid token expiry for stored token - Could not parse from ISO format to datetime.")
            return

        token_struct = TokenStruct(id_token=id_token_from_dict, expiry=token_expiry, from_cache=True, is_jwt=is_jwt)
        if not token_struct.valid:
            LOG.warning("Stored service account token is INVALID")
            return
        if token_struct.expired:
            LOG.debug("Stored service account token has EXPIRED")
            return

        return token_struct

    def _migrate_version(self):
        # Override
        self.discard_existing_tokens()
        return super()._migrate_version()

    # def get_stored_oauth2_token(self, iap_client_id: str):
    #     # TODO: OAuth2
    #     raise NotImplementedError()

    # def store_oauth2_token(self, iap_client_id: str):
    #     # TODO: OAuth2
    #     raise NotImplementedError()


datastore = TokenDatastore(DictBackend)
