import datetime
import json
import requests

from google.auth import jwt

from iaptoolkit.constants import GOOGLE_IAP_PUBLIC_KEY_URL
from iaptoolkit.exceptions import PublicKeyException
from iaptoolkit.exceptions import JWTVerificationFailure


class GooglePublicKeyException(PublicKeyException):
    pass


class GoogleIAPKeys:
    """
    Retrieve Google's public keys for JWT verification and record the timestamp at retrieval.
    If the retrieval was >5m ago (default),  refresh the keys in case of rotation or expiry
    """

    _retrieved_timestamp: datetime.datetime
    _key_ttl_seconds: int = 300  # 5 mins
    _certs: dict

    def __init__(self, key_ttl_seconds: int = 300) -> None:
        self._key_ttl_seconds = key_ttl_seconds
        self.refresh()

    def refresh(self):

        response = requests.get(GOOGLE_IAP_PUBLIC_KEY_URL)
        response.raise_for_status()

        try:
            certs = json.loads(response.text)["keys"]
        except json.JSONDecodeError as ex:
            raise GooglePublicKeyException(f"Decode error in JSON retrieved for Google Public Keys: {ex}")
        except KeyError as ex:
            raise GooglePublicKeyException(f"KeyError with JSON retrieved for Google Public Keys: {ex}")
        if not certs:
            raise GooglePublicKeyException(
                f"Failed to retrieve JSON public keys from Google at: '{GOOGLE_IAP_PUBLIC_KEY_URL}'"
            )

        self._retrieved_timestamp = datetime.datetime.now(tz=datetime.UTC)
        self._certs = certs

    @property
    def should_refresh(self) -> bool:
        if self._retrieved_timestamp > datetime.datetime.now() - datetime.timedelta(
            seconds=self._key_ttl_seconds
        ):
            return False
        return True

    @property
    def certs(self) -> dict:
        if self.should_refresh:
            self.refresh()
        return self._certs.copy()


google_public_keys: GoogleIAPKeys | None = None


def verify_iap_jwt(iap_jwt: str, expected_audience: str|None) -> str:
    global google_public_keys  # Use as singleton
    if not google_public_keys:
        google_public_keys = GoogleIAPKeys()

    decoded_jwt = jwt.decode(iap_jwt, certs=google_public_keys.certs, verify=True)

    # Extract claims
    email = decoded_jwt.get("email")
    audience = decoded_jwt.get("aud")

    if expected_audience and audience != expected_audience:
        raise JWTVerificationFailure("Audience mismatch when verifying IAP JWT")

    return email
