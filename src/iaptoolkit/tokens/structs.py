from dataclasses import dataclass
import datetime
import typing as t

from kvcommon import logger


LOG = logger.get_logger("iaptk")


@dataclass(kw_only=True)
class TokenStruct:
    id_token: str
    expiry: datetime.datetime

    @property
    def expired(self):
        try:
            if not self.expiry:
                # Note that this differs from Google's assumption that an expiry of 'None' means a non-expiring token.
                # We want to err on the side of retrieving a new token instead.
                return True

            # Subtract 60 seconds from expiry to err on the side of avoiding a 401-refresh-retry loop
            skewed_expiry = self.expiry - datetime.timedelta(seconds=60)
            return datetime.datetime.now(datetime.UTC) >= skewed_expiry

        except Exception as ex:
            # TODO: Get rid of blanket-except once we have better test coverage
            LOG.error("Exception when checking token expiry. exception=%s", ex)
            return True


@dataclass(kw_only=True)
class TokenRefreshStruct:
    id_token: str
    token_is_new: bool = True


@dataclass(kw_only=True)
class TokenStructOAuth2(TokenStruct):
    refresh_token: str
    new_refresh_token: bool = False


@dataclass(kw_only=True)
class ResultAddTokenHeader:
    token_added: bool
    token_is_fresh: bool
