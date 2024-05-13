from kvcommon import logger

from iaptoolkit.exceptions import ServiceAccountTokenException
from iaptoolkit.exceptions import TokenStorageException
from iaptoolkit.exceptions import TokenException

from .structs import TokenStruct
from .structs import TokenRefreshStruct

# from .structs import TokenStructOAuth2  # TODO: OAuth2
# from .oauth2 import get_token_for_oauth2  # TODO: OAuth2
# from .service_account import ServiceAccount
from .service_account import GoogleServiceAccount

LOG = logger.get_logger("iaptk")


__all__ = [
    "TokenStruct",
    "TokenRefreshStruct",
    # "TokenStructOAuth2",  # TODO: OAuth2
    "TokenException",
    "TokenStorageException",
]
