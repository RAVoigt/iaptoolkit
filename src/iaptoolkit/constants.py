import pathlib
from pathlib import Path
from importlib.metadata import version
from os.path import expanduser

home = expanduser("~")

IAPTOOLKIT_VERSION = version("iaptoolkit")
IAPTOOLKIT_CONFIG_VERSION = 1

DEFAULT_USE_AUTH_HEADER = True

DEFAULT_CONF_DIR: Path = pathlib.Path.home() / ".iaptoolkit"
DEFAULT_CONF_FILENAME: Path = Path("iaptoolkit.toml")

# https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_proxy-authorization_header
# Default auth header used for IAP-aware requests. Can clash with other uses of that header key.
GOOGLE_IAP_AUTH_HEADER = "Authorization"
# Alternative auth header used for IAP-aware requests when 'Authorization' clashes. Stripped by IAP if consumed.
GOOGLE_IAP_AUTH_HEADER_PROXY = "Proxy-Authorization"
