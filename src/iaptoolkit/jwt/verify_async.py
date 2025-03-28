import asyncio
import datetime

from google.auth import jwt
from google.auth.exceptions import InvalidValue
from google.auth.exceptions import MalformedError

from iaptoolkit.exceptions import JWTInvalidData
from iaptoolkit.exceptions import JWTInvalidAudience
from iaptoolkit.exceptions import JWTMalformed

from .verify import GoogleIAPKeys


class GoogleIAPKeys_Async(GoogleIAPKeys):
    """
    Rudimentary async wrapper class for GoogleIAPKeys using asyncio threads

    Retrieve Google's public keys for JWT verification and record the timestamp at retrieval.
    If the retrieval was >5m ago (default),  refresh the keys in case of rotation or expiry
    """

    _retrieved_timestamp: datetime.datetime
    _key_ttl_seconds: int = 300  # 5 mins
    _certs: dict

    def __init__(self, key_ttl_seconds: int = 300) -> None:
        self._key_ttl_seconds = key_ttl_seconds

    async def refresh_async(self):
        await asyncio.to_thread(self.refresh)

    @property
    async def certs(self) -> dict:
        if self.should_refresh:
            await self.refresh_async()
        return self._certs.copy()


google_public_keys_async: GoogleIAPKeys_Async | None = None

async def get_google_public_keys() -> GoogleIAPKeys_Async:
    global google_public_keys_async  # Use as singleton
    if not google_public_keys_async:
        google_public_keys_async = GoogleIAPKeys_Async()
        await google_public_keys_async.refresh_async()
    return google_public_keys_async



async def verify_iap_jwt_async(iap_jwt: str, expected_audience: str|None) -> str:
    # Rudimentary async wrapper func for verify_iap_jwt using asyncio threads until google.auth.jwt_async is public

    google_public_keys_async = await get_google_public_keys()

    try:
        decoded_jwt = await asyncio.to_thread(
            jwt.decode,
            iap_jwt,
            certs=await google_public_keys_async.certs,
            verify=True
        )
    except InvalidValue as ex:
        raise JWTInvalidData(google_exception=ex)
    except MalformedError as ex:
        raise JWTMalformed(google_exception=ex)

    # Extract claims
    email = decoded_jwt.get("email")
    audience = decoded_jwt.get("aud")

    if expected_audience and audience != expected_audience:
        raise JWTInvalidAudience()

    return email
