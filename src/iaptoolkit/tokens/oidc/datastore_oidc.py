import datetime
import typing as t

from kvcommon import logger

from iaptoolkit.tokens.token_datastore import TokenDatastore


LOG = logger.get_logger("iaptk-ds-oidc")


class TokenDatastore_OIDC(TokenDatastore):
    _tokens_key: str = "oidc_tokens"

    def get_stored_token(self, iap_client_id: str) -> dict | None:
        tokens_dict = self.get_or_create_nested_dict(self._tokens_key)
        token_struct_dict = self._retrieve_hashed_dict_entry(
            target=tokens_dict, source_key=iap_client_id
        )
        if not token_struct_dict:
            LOG.debug("No stored service account token for current iap_client_id")
            return
        return token_struct_dict

    def store_token(self, iap_client_id: str, id_token: str, token_expiry: datetime.datetime):
        tokens_dict = self.get_or_create_nested_dict(self._tokens_key)

        # TODO: Encode/encrypt token?
        value = dict(id_token=id_token, token_expiry=token_expiry.isoformat())
        self._insert_hashed_dict_entry(target=tokens_dict, source_key=iap_client_id, value=value)

        try:
            self.update_data(oidc_tokens=tokens_dict)
        except OSError as ex:
            LOG.error("Failed to store service account token for re-use. exception=%s", ex)
