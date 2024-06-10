import datetime
from abc import ABC, abstractmethod

from kvcommon import logger

from iaptoolkit.exceptions import TokenStorageException
from iaptoolkit.tokens.token_datastore import TokenDatastore

from iaptoolkit.tokens.structs import TokenStruct


LOG = logger.get_logger("iaptk")


class BaseTokenInterface(ABC):
    _datastore: TokenDatastore
    _iap_client_id: str

    def __init__(self, datastore: TokenDatastore, iap_client_id: str) -> None:
        super().__init__()
        self._iap_client_id = iap_client_id
        self._datastore = datastore

    @abstractmethod
    def _get_stored_token(self) -> dict | None:
        raise NotImplementedError()

    @abstractmethod
    def _store_token(self, iap_client_id: str, id_token: str, token_expiry: datetime.datetime):
        raise NotImplementedError()

    def get_stored_token(self) -> TokenStruct | None:
        try:
            token_dict = self._get_stored_token()
            if (
                not token_dict
                or not token_dict.get("id_token", None)
                or not token_dict.get("token_expiry", None)
            ):
                LOG.debug("No stored token for supplied client_id(s)")
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
                LOG.debug("Invalid token expiry for supplied client_id(s)")
                return

            token_struct = TokenStruct(id_token=id_token_from_dict, expiry=token_expiry)
            if token_struct.expired:
                LOG.debug("Stored OAuth2 token for supplied client_id(s) has EXPIRED")
                return
            return token_struct

        except Exception as ex:
            # Err on the side of not letting token-caching break requests, hence blanket except
            # Caller can `try/except TokenStorageException` for safety
            raise TokenStorageException(
                f"Exception when trying to retrieve stored token. exception={ex}"
            )