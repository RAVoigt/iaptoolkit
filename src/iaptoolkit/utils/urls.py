import typing as t
from urllib.parse import ParseResult

from kvcommon import logger
from kvcommon.urls import get_netloc_without_port_from_url_parts

from iaptoolkit.exceptions import InvalidDomain

LOG = logger.get_logger("iaptk")


def is_url_safe_for_token(
    url_parts: ParseResult, allowed_domains: t.Optional[t.List[str] | t.Set[str] | t.Tuple[str]] = None
) -> bool:
    """Determines if the given url is considered a safe to receive a token in request headers.

    If URL validation is enabled, check that the URL's netloc is in the list of valid domains.
    """
    if not isinstance(url_parts, ParseResult):
        raise TypeError(
            f"Invalid url_parts - Expected a ParseResult - Got: "
            f"'{str(url_parts)}' (type#: {type(url_parts).__name__})"
        )
    if allowed_domains is not None and not isinstance(allowed_domains, (list, set, tuple)) :
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
