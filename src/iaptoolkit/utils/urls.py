from dataclasses import dataclass
import httpx
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
    url: str
    protected: bool = False
    iap_audience: str | None = None


def _determine_iap_state_from_response(response: requests.Response | httpx.Response, url: str):
    # This approach may not be reliable - Undocumented?

    iap_audience = None
    requires_iap = False

    if response.status_code == 302:
        location = response.headers.get("location")
        qs = str(urlparse(location).query)
        query = parse_qs(qs) or {}
        if "client_id" in query:
            iap_audience = str(query["client_id"][0])
            requires_iap = True

    return IAPURLState(url=url, protected=requires_iap, iap_audience=iap_audience)


def get_url_iap_state(url: str) -> IAPURLState:
    response = requests.get(url, allow_redirects=False)
    return _determine_iap_state_from_response(response, url)


async def get_url_iap_state_async(url: str) -> IAPURLState:
    async with httpx.AsyncClient() as client:
        response = await client.get(url, follow_redirects=False)
        return _determine_iap_state_from_response(response, url)


def is_url_iap_protected(url: str) -> bool:
    url_state: IAPURLState = get_url_iap_state(url)
    return url_state.protected

async def is_url_iap_protected_async(url: str) -> bool:
    url_state: IAPURLState = await get_url_iap_state_async(url)
    return url_state.protected


def _handle_url_state_for_audience(url_state: IAPURLState) -> str | None:
    if not url_state.protected:
        raise IAPClientIDException(f"URL does not appear to be IAP-protected: '{url_state.url}'")

    iap_audience = url_state.iap_audience
    if not iap_audience:
        raise IAPClientIDException(
            f"No client_id returned in redirect for query when trying to retrieve IAP Client ID for url: '{url_state.url}'"
        )
    return iap_audience


def get_iap_audience_for_url(url: str) -> str | None:
    url_state: IAPURLState = get_url_iap_state(url)

# TODO: Legacy terminology - Deprecate
get_iap_client_id_for_url = get_iap_audience_for_url


async def get_iap_audience_for_url_async(url: str) -> str | None:
    url_state: IAPURLState = await get_url_iap_state_async(url)
    return _handle_url_state_for_audience(url_state)
