import datetime
from pathlib import Path
import typing as t

from kvcommon import logger

from iaptoolkit.constants import DEFAULT_CONF_DIR
from iaptoolkit.constants import DEFAULT_CONF_FILENAME

from iaptoolkit.tokens.structs import TokenStruct
from iaptoolkit.tokens.token_datastore import TokenDatastoreTOML


LOG = logger.get_logger("iaptk-ds-oauth2")


class TokenDatastore_OAuth2(TokenDatastoreTOML):
    _tokens_key: str = "outh2_tokens"
    _refresh_tokens_key: str = "outh2_refresh_tokens"

    @staticmethod
    def get_token_key(iap_client_id: str, client_id: str) -> str:
        return f"{iap_client_id}::{client_id}"

    def __init__(
        self, storage_dir_path: str | Path = DEFAULT_CONF_DIR, filename: str | Path = DEFAULT_CONF_FILENAME
    ) -> None:
        super().__init__(storage_dir_path, filename)

    def _get_stored_token(self, tokens_key: str, iap_client_id: str, client_id: str) -> TokenStruct | None:

        tokens_dict = self.get_or_create_nested_dict(tokens_key)
        source_key = self.get_token_key(iap_client_id, client_id)
        token_struct_dict = self._retrieve_hashed_dict_entry(target=tokens_dict, source_key=source_key)

        if not token_struct_dict:
            LOG.debug("No stored token in '%s' for given iap_client_id", tokens_key)
            return

        id_token = token_struct_dict.get("id_token", None)
        token_expiry = token_struct_dict.get("token_expiry", None)
        token_expiry = datetime.datetime.fromisoformat(token_expiry)
        token_expiry.replace(tzinfo=datetime.UTC)
        if not id_token:
            LOG.debug("Invalid token data retrieved from '%s': No id_token", tokens_key)
            return
        if not token_expiry:
            LOG.debug("Invalid token data retrieved from '%s': No token_expiry", tokens_key)
            return

        return TokenStruct(id_token=id_token, expiry=token_expiry, from_cache=True)

    def get_stored_token(self, iap_client_id: str, client_id: str) -> TokenStruct | None:
        return self._get_stored_token(self._tokens_key, iap_client_id=iap_client_id, client_id=client_id)

    def get_stored_refresh_token(self, iap_client_id: str, client_id: str) -> TokenStruct | None:
        return self._get_stored_token(self._refresh_tokens_key, iap_client_id=iap_client_id, client_id=client_id)

    def _store_token(
        self, token_type: str, iap_client_id: str, client_id: str, id_token: str, token_expiry: datetime.datetime
    ):
        # TODO: Clean this up
        if token_type == "token":
            tokens_dict = self.get_or_create_nested_dict(self._tokens_key)
        elif token_type == "refresh":
            tokens_dict = self.get_or_create_nested_dict(self._refresh_tokens_key)
        else:
            raise ValueError(f"Invalid token_type: {token_type}")

        # TODO: Encode/encrypt token?
        value = dict(id_token=id_token, token_expiry=token_expiry.isoformat())
        source_key = self.get_token_key(iap_client_id, client_id)
        self._insert_hashed_dict_entry(target=tokens_dict, source_key=source_key, value=value)

        try:
            if token_type == "token":
                self.update_data(outh2_tokens=tokens_dict)
            elif token_type == "refresh":
                self.update_data(outh2_refresh_tokens=tokens_dict)
        except OSError as ex:
            LOG.error("Failed to store '%s' token for re-use. Exception=%s", token_type, ex)

    def store_token(self, iap_client_id: str, client_id: str, id_token: str, token_expiry: datetime.datetime):
        self._store_token(
            "token", iap_client_id=iap_client_id, client_id=client_id, id_token=id_token, token_expiry=token_expiry
        )

    def store_refresh_token(self, iap_client_id: str, client_id: str, refresh_token: str, token_expiry: datetime.datetime):
        self._store_token(
            "refresh", iap_client_id=iap_client_id, client_id=client_id, id_token=refresh_token, token_expiry=token_expiry
        )
