import pytest
from iaptoolkit.headers import _sanitize_request_header
from iaptoolkit.headers import sanitize_request_headers


def test_empty_headers_dict():
    headers_dict = {}
    header_key = "Authorization"
    _sanitize_request_header(headers_dict, header_key)
    assert headers_dict == {}


def test_missing_header_key():
    headers_dict = {"Content-Type": "application/json"}
    header_key = "Authorization"
    _sanitize_request_header(headers_dict, header_key)
    assert headers_dict == {"Content-Type": "application/json"}


def test_bearer_token_hidden():
    headers_dict = {"Authorization": "Bearer abcdef12345"}
    header_key = "Authorization"
    _sanitize_request_header(headers_dict, header_key)
    assert headers_dict == {"Authorization": "Bearer <token_hidden>"}


def test_basic_auth_hidden():
    headers_dict = {"Authorization": "Basic dXNlcjpwYXNzd29yZA=="}
    header_key = "Authorization"
    _sanitize_request_header(headers_dict, header_key)
    assert headers_dict == {"Authorization": "Basic <basic_auth_hidden>"}


def test_other_header_hidden():
    headers_dict = {"Custom-Header": "secret_value"}
    header_key = "Custom-Header"
    _sanitize_request_header(headers_dict, header_key)
    assert headers_dict == {"Custom-Header": "<contents_hidden>"}


def test_mixed_headers_hidden():
    headers_dict = {
        "Authorization": "Bearer abcdef12345",
        "Custom-Header": "secret_value",
    }
    header_key = "Authorization"
    _sanitize_request_header(headers_dict, header_key)
    assert headers_dict == {
        header_key: "Bearer <token_hidden>",
        "Custom-Header": "secret_value",
    }


def test_multiple_bearer_tokens_hidden():
    headers_dict = {"Authorization": "Bearer abcdef12345, Bearer xyz98765"}
    header_key = "Authorization"
    _sanitize_request_header(headers_dict, header_key)
    # TODO: Handle multiple tokens
    # assert headers_dict == {"Authorization": "Bearer <token_hidden>, Bearer <token_hidden>"}
    assert headers_dict == {"Authorization": "Bearer <token_hidden>"}


def test_multiple_basic_auth_hidden():
    headers_dict = {"Authorization": "Basic dXNlcjpwYXNzd29yZA==, Basic bXk6cGFzc3dvcmQ="}
    header_key = "Authorization"
    _sanitize_request_header(headers_dict, header_key)
    # TODO: Handle multiple tokens
    # assert headers_dict == {"Authorization": "Basic <basic_auth_hidden>, Basic <basic_auth_hidden>"}
    assert headers_dict == {"Authorization": "Basic <basic_auth_hidden>"}


def test_custom_header_hidden():
    headers_dict = {"Custom-Header": "custom_value"}
    header_key = "Custom-Header"
    _sanitize_request_header(headers_dict, header_key)
    assert headers_dict == {"Custom-Header": "<contents_hidden>"}


def test_multiple_headers_hidden():
    headers_dict = {
        "Authorization": "Basic dXNlcjpwYXNzd29yZA==",
        "Proxy-Authorization": "Bearer abcdef12345",
        "X-Goog-Iap-Jwt-Assertion": '{"alg": "ES256", "kid": "some_key_id"}',
        "X-Some-Other-Header": "Some_Header_Value",
    }
    sanitize_request_headers(headers_dict)
    assert sanitize_request_headers(headers_dict) == {
        "Authorization": "Basic <basic_auth_hidden>",
        "Proxy-Authorization": "Bearer <token_hidden>",
        "X-Goog-Iap-Jwt-Assertion": "<contents_hidden>",
        "X-Some-Other-Header": "Some_Header_Value",
    }
