from dataclasses import dataclass
import datetime
import typing as t

from kvcommon import logger


LOG = logger.get_logger("iaptk")


def validate_token(token: str | None) -> bool:
    if not isinstance(token, str) or token.strip() == "":
        return False

    return True


# @dataclass(kw_only=True)
class TokenStruct:
    id_token: str
    expiry: datetime.datetime
    from_cache: bool = False

    def __init__(self, id_token: str, expiry: datetime.datetime, from_cache: bool = False) -> None:
        if not id_token:
            raise ValueError("Empty/Invalid id_token for TokenStruct")
        if not isinstance(expiry, datetime.datetime):
            raise ValueError("Invalid expiry for TokenStruct")
        self.id_token = id_token
        self.expiry = expiry
        self.from_cache = from_cache


    @property
    def expired(self) -> bool:
        try:
            if not self.expiry:
                # Note that this differs from Google's assumption that an expiry of 'None' means a non-expiring token.
                # We want to err on the side of retrieving a new token instead.
                return True

            # Subtract 60 seconds from expiry to err on the side of avoiding a 401-refresh-retry loop
            skewed_expiry = self.expiry - datetime.timedelta(seconds=60)
            return datetime.datetime.now(datetime.UTC) >= skewed_expiry

        except TypeError as ex:
            LOG.error("TypeError Exception when checking token expiry. exception=%s", ex)
            return False
        except Exception as ex:
            # TODO: Get rid of blanket-except once we have better test coverage
            LOG.error("Exception when checking token expiry. exception=%s", ex)
            return True

    @property
    def valid(self):
        return validate_token(self.id_token)


@dataclass(kw_only=True)
class ResultAddTokenHeader:
    token_added: bool
    token_is_fresh: bool
