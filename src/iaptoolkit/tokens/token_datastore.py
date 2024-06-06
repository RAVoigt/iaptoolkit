import datetime
import typing as t

from kvcommon import logger
from kvcommon.datastore.backend import DatastoreBackend
from kvcommon.datastore.backend import DictBackend
# from kvcommon.datastore.backend import TOMLBackend
from kvcommon.datastore import VersionedDatastore

from iaptoolkit.constants import IAPTOOLKIT_CONFIG_VERSION


LOG = logger.get_logger("iaptk-ds")


class TokenDatastore(VersionedDatastore):
    _service_account_tokens_key = "service_account_tokens"

    def __init__(self, backend: DatastoreBackend | type[DatastoreBackend]) -> None:
        super().__init__(backend=backend, config_version=IAPTOOLKIT_CONFIG_VERSION)
        self._ensure_tokens_dict()

    def _ensure_tokens_dict(self):
        tokens_dict = self.get_or_create_nested_dict("tokens")
        if "refresh" not in tokens_dict.keys():
            tokens_dict["refresh"] = None
        self.set_value("tokens", tokens_dict)

    def discard_existing_tokens(self):
        LOG.debug("Discarding existing tokens.")
        self.update_data(tokens={})

    def get_stored_service_account_token(self, iap_client_id: str) -> t.Optional[dict]:
        tokens_dict = self.get_or_create_nested_dict(self._service_account_tokens_key)
        token_struct_dict = tokens_dict.get(iap_client_id, None)
        if not token_struct_dict:
            LOG.debug("No stored service account token for current iap_client_id")
            return
        return token_struct_dict

    def store_service_account_token(
        self, iap_client_id: str, id_token: str, token_expiry: datetime.datetime
    ):
        tokens_dict = self.get_or_create_nested_dict(self._service_account_tokens_key)
        tokens_dict[iap_client_id] = dict(id_token=id_token, token_expiry=token_expiry.isoformat())

        try:
            self.update_data(service_account_tokens=tokens_dict)
        except OSError as ex:
            LOG.error("Failed to store service account token for re-use. exception=%s", ex)

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

# if PERSISTENT_DATASTORE_ENABLED:
#     datastore_toml = TokenDatastore(TOMLBackend(PERSISTENT_DATASTORE_PATH, PERSISTENT_DATASTORE_USERNAME))
