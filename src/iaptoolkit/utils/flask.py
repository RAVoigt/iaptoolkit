import typing as t
from functools import wraps

from flask import request
from flask.wrappers import Response

from iaptoolkit.constants import GOOGLE_IAP_JWT_HEADER_KEY
from iaptoolkit.exceptions import JWTDisallowedUser
from iaptoolkit.exceptions import JWTInvalidAudience
from iaptoolkit.exceptions import JWTInvalidData
from iaptoolkit.exceptions import JWTMalformed
from iaptoolkit.utils.verify import verify_iap_jwt


def requires_iap_jwt(
        jwt_audience: str,
        allowed_users: set[str],
        response_cls: Response = Response,
        jwt_header_key: str = GOOGLE_IAP_JWT_HEADER_KEY
    ):
    """
    A decorator that ensures the incoming request has a valid IAP JWT for a Flask route,
    and that the user in the JWT has permission for the route
    """
    def decorator(f):

        @wraps(f)
        def decorated_function(*args, **kwargs):

            jwt_header: str = request.headers.get(jwt_header_key.lower(), None)
            if not jwt_header:
                return response_cls(f"No Google IAP JWT header in request at key: '{jwt_header_key}'", status=401)

            try:
                user_email = verify_iap_jwt(iap_jwt=jwt_header, expected_audience=jwt_audience)
                if not user_email:
                    raise JWTInvalidData("No user_email in decoded JWT")

                if allowed_users and user_email not in allowed_users:
                    raise JWTDisallowedUser(message=f"User '{user_email}' from JWT not allowed on route")

            except (JWTInvalidData, JWTMalformed) as ex:
                return response_cls(f"Forbidden: '{ex.message}'", status=401)

            except (JWTInvalidAudience, JWTDisallowedUser) as ex:
                return response_cls(f"Forbidden: '{ex.message}'", status=403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator
