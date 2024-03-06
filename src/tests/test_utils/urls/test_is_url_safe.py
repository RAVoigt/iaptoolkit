from urllib.parse import urlparse, ParseResult
from typing import List
import pytest

from iaptoolkit.utils.urls import is_url_safe_for_token
from iaptoolkit.utils.urls import InvalidDomain


@pytest.fixture
def valid_domains():
    return ["example.com", "example.org"]


def test_is_url_safe_for_token_no_validation():
    url = urlparse("https://example.com/path")
    assert is_url_safe_for_token(url)


def test_is_url_safe_for_token_empty_validation():
    url = urlparse("https://example.com/path")
    assert is_url_safe_for_token(url, [])


def test_is_url_safe_for_token_valid_domain(valid_domains):
    url = urlparse("https://example.com/path")
    assert is_url_safe_for_token(url, valid_domains)


def test_is_url_safe_for_token_invalid_domain(valid_domains):
    url = urlparse("https://invalid.com/path")
    assert not is_url_safe_for_token(url, valid_domains)


def test_is_url_safe_for_token_subdomain(valid_domains):
    url = urlparse("https://sub.example.com/path")
    assert is_url_safe_for_token(url, valid_domains)


def test_is_url_safe_for_token_case_sensitive(valid_domains):
    url = urlparse("https://EXAMPLE.com/path")
    # Hosts are not case sensitive, but better to err on the side of caution here
    assert not is_url_safe_for_token(url, valid_domains)


def test_is_url_safe_for_token_with_port(valid_domains):
    url = urlparse("https://example.com:8080/path")
    assert is_url_safe_for_token(url, valid_domains)


def test_is_url_safe_for_token_multiple_valid_domains():
    url = urlparse("https://test.org/path")
    assert is_url_safe_for_token(url, ["example.com", "test.org"])


def test_is_url_safe_for_token_no_valid_domains():
    url = urlparse("https://example.com/path")
    assert is_url_safe_for_token(url, None)


def test_is_url_safe_for_token_empty_url(valid_domains):
    with pytest.raises(TypeError):
        is_url_safe_for_token("", valid_domains)  # type: ignore
    url = urlparse("")
    assert not is_url_safe_for_token(url, valid_domains)


def test_is_url_safe_for_token_invalid_url(valid_domains):
    with pytest.raises(TypeError):
        is_url_safe_for_token(None, valid_domains)  # type: ignore


def test_is_url_safe_for_token_invalid_url_parts_type(valid_domains):
    with pytest.raises(TypeError):
        is_url_safe_for_token("not a ParseResult", valid_domains)  # type: ignore


def test_is_url_safe_for_token_invalid_valid_domains_type():
    url = urlparse("https://example.com/path")
    with pytest.raises(TypeError):
        is_url_safe_for_token(url, "not a list")  # type: ignore


def test_is_url_safe_for_token_invalid_valid_domains_item_type():
    url = urlparse("https://example.com/path")
    with pytest.raises(InvalidDomain):
        is_url_safe_for_token(url, [123, "example.com"])  # type: ignore


def test_is_url_safe_for_token_empty_url_and_valid_domains():
    url = urlparse("")
    assert not is_url_safe_for_token(url, None)


def test_is_url_safe_for_token_no_valid_domain(valid_domains):
    url = urlparse("https://example.com/path")
    assert not is_url_safe_for_token(url, ["invalid.com"])


def test_is_url_safe_for_token_no_netloc():
    url = ParseResult(scheme="https", netloc="", path="/path", params="", query="", fragment="")
    assert not is_url_safe_for_token(url)
