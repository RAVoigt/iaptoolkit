import os
import typing as t

from kvcommon.types import to_bool

IAPTOOLKIT_CONFIG_VERSION = 1

PERSISTENT_DATASTORE_ENABLED = to_bool(os.getenv("IAPTOOLKIT_PERSISTENT_DATASTORE_ENABLED", False))
PERSISTENT_DATASTORE_PATH = os.getenv("IAPTOOLKIT_PERSISTENT_DATASTORE_PATH", "~/.iaptoolkit")
PERSISTENT_DATASTORE_USERNAME = os.getenv("IAPTOOLKIT_PERSISTENT_DATASTORE_USERNAME", "user.toml")


GOOGLE_IAP_CLIENT_ID = os.getenv("IAP_GOOGLE_IAP_CLIENT_ID", "")
GOOGLE_CLIENT_ID = os.getenv("IAP_GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("IAP_GOOGLE_CLIENT_SECRET", "")

"""
If true, insert Google IAP auth tokens in the 'Authorization' header if available/unused,
instead of the 'Proxy-Authorization'.

Default: False
"""
IAPTOOLKIT_USE_AUTH_HEADER = to_bool(os.getenv("IAPTOOLKIT_USE_AUTH_HEADER", True))
