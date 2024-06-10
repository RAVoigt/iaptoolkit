import datetime
import hashlib
import typing as t
from abc import abstractmethod

from kvcommon import logger
from kvcommon.datastore.backend import DatastoreBackend
from kvcommon.datastore import VersionedDatastore

from iaptoolkit.constants import IAPTOOLKIT_CONFIG_VERSION


LOG = logger.get_logger("iaptk-ds")


class TokenDatastore(VersionedDatastore):
    _tokens_key: str

    def __init__(self, backend: DatastoreBackend | type[DatastoreBackend]) -> None:
        super().__init__(backend=backend, config_version=IAPTOOLKIT_CONFIG_VERSION)
        self._ensure_tokens_dict()

    def _migrate_version(self):
        # Override
        self.discard_existing_tokens()
        return super()._migrate_version()

    def _ensure_tokens_dict(self):
        tokens_dict = self.get_or_create_nested_dict("tokens")
        if "refresh" not in tokens_dict.keys():
            tokens_dict["refresh"] = None
        self.set_value("tokens", tokens_dict)

    @staticmethod
    def _insert_hashed_dict_entry(target: dict, source_key: str, value: t.Any):
        hash_obj = hashlib.sha256(source_key.encode("utf-8"))
        hex_digest = hash_obj.hexdigest()
        target[hex_digest] = value

    @staticmethod
    def _retrieve_hashed_dict_entry(target: dict, source_key: str) -> t.Any:
        hash_obj = hashlib.sha256(source_key.encode("utf-8"))
        hex_digest = hash_obj.hexdigest()
        # TODO: Check collisions/pre-existing keys?
        target.get(hex_digest)

    def discard_existing_tokens(self):
        LOG.debug("Discarding existing tokens.")
        self.update_data(tokens={})

    @abstractmethod
    def get_stored_token(self, iap_client_id: str) -> dict | None:
        raise NotImplementedError

    @abstractmethod
    def store_token(self, iap_client_id: str, id_token: str, token_expiry: datetime.datetime):
        raise NotImplementedError


# datastore = TokenDatastore(DictBackend)

# if PERSISTENT_DATASTORE_ENABLED:
#     datastore_toml = TokenDatastore(TOMLBackend(PERSISTENT_DATASTORE_PATH, PERSISTENT_DATASTORE_USERNAME))
