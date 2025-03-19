from dataclasses import dataclass
import requests
import typing as t
from urllib.parse import parse_qs
from urllib.parse import ParseResult
from urllib.parse import urlparse

from kvcommon import logger
from kvcommon.urls import get_netloc_without_port_from_url_parts

from iaptoolkit.exceptions import IAPClientIDException
from iaptoolkit.exceptions import InvalidDomain

LOG = logger.get_logger("iaptk")


def is_url_safe_for_token(
    url_parts: ParseResult, allowed_domains: t.Optional[t.List[str] | t.Set[str] | t.Tuple[str]] = None,
) -> bool:
    """Determines if the given url is considered a safe to receive a token in request headers.

    If URL validation is enabled, check that the URL's netloc is in the list of valid domains.
    """
    if not isinstance(url_parts, ParseResult):
        raise TypeError(
            f"Invalid url_parts - Expected a ParseResult - Got: "
            f"'{str(url_parts)}' (type#: {type(url_parts).__name__})"
        )

    if allowed_domains is not None and not isinstance(allowed_domains, (list, set, tuple)):
        raise TypeError("allowed_domains must be a list, set or tuple if not None")

    netloc = get_netloc_without_port_from_url_parts(url_parts)
    if not netloc:
        return False

    if not allowed_domains:
        return True

    for domain in allowed_domains:
        if domain == "" or not isinstance(domain, str):
            raise InvalidDomain(
                f"Empty or non-string domain in allowed_domains: "
                f"'{str(domain)}' (type#: {type(domain).__name__})"
            )

        if netloc.endswith(domain):
            return True

    return False


@dataclass(kw_only=True)
class IAPURLState:
    protected: bool = False
    iap_client_id: str | None = None


def get_url_iap_state(url: str) -> IAPURLState:
    # This approach may not be reliable - Undocumented?

    iap_client_id = None
    requires_iap = False

    response = requests.get(url, allow_redirects=False)
    if response.status_code == 302:
        location = response.headers.get("location")
        qs = str(urlparse(location).query)
        query = parse_qs(qs) or {}
        if "client_id" in query:
            iap_client_id = str(query["client_id"][0])
            requires_iap = True

    return IAPURLState(protected=requires_iap, iap_client_id=iap_client_id)


def is_url_iap_protected(url: str) -> bool:
    url_state: IAPURLState = get_url_iap_state(url)
    return url_state.protected


def get_iap_client_id_for_url(url: str) -> str | None:
    url_state: IAPURLState = get_url_iap_state(url)
    if not url_state.protected:
        raise IAPClientIDException(f"URL does not appear to be IAP-protected: '{url}'")

    iap_client_id = url_state.iap_client_id
    if not iap_client_id:
        raise IAPClientIDException(
            f"No client_id returned in redirect for query when trying to retrieve IAP Client ID for url: '{url}'"
        )
    return iap_client_id
