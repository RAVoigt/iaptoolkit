import datetime

import mock
import pytest

from iaptoolkit.tokens.structs import TokenStruct
from iaptoolkit.exceptions import TokenStorageException
from iaptoolkit.tokens.service_account import ServiceAccount


@mock.patch("iaptoolkit.tokens.token_datastore.datastore.get_stored_service_account_token")
def test_no_stored_token(mock_datastore):
    mock_datastore.return_value = None
    result = ServiceAccount.get_stored_token("test_iap_audience")
    assert result is None


# TODO: Fix for having moved validation logic to datastore
# @mock.patch("iaptoolkit.tokens.token_datastore.datastore.get_stored_service_account_token")
# def test_invalid_stored_token(mock_datastore):
#     mock_datastore.return_value = {"id_token": None, "token_expiry": None}
#     result = ServiceAccount.get_stored_token("test_iap_audience")
#     assert result is None


# TODO: Fix for having moved validation logic to datastore
# @mock.patch("iaptoolkit.tokens.token_datastore.datastore.get_stored_service_account_token")
# def test_invalid_id_token(mock_datastore):
#     mock_datastore.return_value = {"id_token": None, "token_expiry": "2022-01-01T00:00:00"}
#     result = ServiceAccount.get_stored_token("test_iap_audience")
#     assert result is None

# TODO: Fix for having moved validation logic to datastore
# @mock.patch("iaptoolkit.tokens.token_datastore.datastore.get_stored_service_account_token")
# def test_invalid_token_expiry(mock_datastore):
#     mock_datastore.return_value = {"id_token": "valid_token", "token_expiry": "invalid_expiry"}
#     result = ServiceAccount.get_stored_token("test_iap_audience")
#     assert result is None


@mock.patch("iaptoolkit.tokens.token_datastore.datastore.get_stored_service_account_token")
def test_expired_token(mock_datastore):
    # expired_expiry = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    mock_datastore.return_value = None
    result = ServiceAccount.get_stored_token("test_iap_audience")
    assert result is None


# TODO: Fix for having moved validation logic to datastore
# @mock.patch("iaptoolkit.tokens.token_datastore.datastore.get_stored_service_account_token")
# def test_valid_token(mock_datastore):
#     future_expiry = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
#     mock_datastore.return_value = TokenStruct(id_token="valid_token", expiry=future_expiry, from_cache=True, is_jwt=False)
#     result = ServiceAccount.get_stored_token("test_iap_audience")
#     assert isinstance(result, TokenStruct)
#     assert result.id_token == "valid_token"
#     assert result.expiry == future_expiry


@mock.patch("iaptoolkit.tokens.token_datastore.datastore.get_stored_service_account_token")
def test_exception_on_datastore_error(mock_datastore):
    mock_datastore.side_effect = Exception("Datastore error")
    with pytest.raises(TokenStorageException):
        ServiceAccount.get_stored_token("test_iap_audience")
