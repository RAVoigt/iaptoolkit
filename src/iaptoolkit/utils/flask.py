from enum import StrEnum
import typing as t
from functools import wraps

from flask import request
from flask.wrappers import Request
from flask.wrappers import Response

try:
    from prometheus_client import Counter
except ImportError:
    pass

from iaptoolkit.constants import GOOGLE_IAP_JWT_HEADER_KEY
from iaptoolkit.exceptions import JWTDisallowedUser
from iaptoolkit.exceptions import JWTInvalidAudience
from iaptoolkit.exceptions import JWTInvalidData
from iaptoolkit.exceptions import JWTMalformed
from iaptoolkit.utils.verify import verify_iap_jwt


# TODO move to constants
class JWT_Event(StrEnum):
    SUCCESS = "success"
    FAIL_NO_HEADER = "fail_no_header"
    FAIL_INVALID_JWT = "fail_invalid"
    FAIL_NO_EMAIL = "fail_no_email"
    FAIL_WRONG_USER = "fail_wrong_user"
    FAIL_WRONG_AUDIENCE = "fail_wrong_audience"

try:
    from prometheus_client import Counter
    # TODO move to constants
    default_metric = Counter(
        "iaptoolkit_jwt_event_total",
        "Count of JWT verification events",
        labelnames=["event"]
    )
except ImportError:
    default_metric = None


def _inc_metric(metric: Counter | None, event: str):
    if not metric:
        return
    metric.labels(event=event).inc()


def _verify_jwt(
        request: Request,
        jwt_header_key: str,
        jwt_audience: str,
        allowed_users: set[str] | None = None,
        response_cls: t.Type[Response] = Response,
        metric: Counter | None = default_metric
    ) -> Response | None:
    jwt_header: str = request.headers.get(jwt_header_key.lower(), "")
    if not jwt_header:
        _inc_metric(metric, event=JWT_Event.FAIL_NO_HEADER)
        return response_cls(f"No Google IAP JWT header in request at key: '{jwt_header_key}'", status=401)

    try:
        user_email = verify_iap_jwt(iap_jwt=jwt_header, expected_audience=jwt_audience)
        if not user_email:
            raise JWTInvalidData("No user_email in decoded JWT")

        if allowed_users and user_email not in allowed_users:
            raise JWTDisallowedUser(message=f"User '{user_email}' from JWT not allowed for route")

    except (JWTInvalidData, JWTMalformed) as ex:
        _inc_metric(metric, event=JWT_Event.FAIL_INVALID_JWT)
        return response_cls(f"Forbidden: '{ex.message}'", status=401)

    except JWTInvalidAudience as ex:
        _inc_metric(metric, event=JWT_Event.FAIL_WRONG_AUDIENCE)
        return response_cls(f"Forbidden: '{ex.message}'", status=403)

    except JWTDisallowedUser as ex:
        _inc_metric(metric, event=JWT_Event.FAIL_WRONG_USER)
        return response_cls(f"Forbidden: '{ex.message}'", status=403)

    return None


def requires_iap_jwt(
        jwt_audience: str,
        response_cls: t.Type[Response] = Response,
        jwt_header_key: str = GOOGLE_IAP_JWT_HEADER_KEY,
        metric: Counter | None = default_metric
    ):
    """
    A decorator that ensures the incoming request has a valid IAP JWT for a Flask route,
    and that the user in the JWT has permission for the route.

    Params:
        jwt_audience: JWT Audience string (or IAP Client ID) to verify JWT against
        response_cls: Flask response class or subclass thereof to return from decorator
        jwt_header_key: request header key from which to retrieve the JWT (Default: 'x-goog-iap-jwt-assertion')
        metric:
            prometheus_client.Counter object (or None) to inc() for different outcomes.
            Must have a single label: 'event'.
            Set metric param to 'None' to disable metrics.

    Returns:
        Flask response of type determined by response_cls param on JWT Failure, else result of decorated view function
    """
    def decorator(f: t.Callable) -> t.Callable:

        @wraps(f)
        def decorated_function(*args, **kwargs) -> Response:
            resp: Response | None = _verify_jwt(
                request,
                jwt_header_key=jwt_header_key,
                jwt_audience=jwt_audience,
                allowed_users=None,
                response_cls=response_cls,
                metric=metric
            )
            if resp is not None:
                return resp
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def requires_iap_jwt_valid_user(
        jwt_audience: str,
        allowed_users: set[str],
        response_cls: t.Type[Response] = Response,
        jwt_header_key: str = GOOGLE_IAP_JWT_HEADER_KEY,
        metric: Counter | None = default_metric
    ):
    """
    A decorator that ensures the incoming request has a valid IAP JWT for a Flask route,
    and that the user in the JWT has permission for the route

    Params:
        jwt_audience: JWT Audience string (or IAP Client ID) to verify JWT against
        allowed_users: set of email strings to check against user_email in JWT for permission to access decorated view func
        response_cls: Flask response class or subclass thereof to return from decorator
        jwt_header_key: request header key from which to retrieve the JWT (Default: 'x-goog-iap-jwt-assertion')
        metric:
            prometheus_client.Counter object (or None) to inc() for different outcomes.
            Must have a single label: 'event'.
            Set metric param to 'None' to disable metrics.

    Returns:
        Flask response of type determined by response_cls param on JWT Failure, else result of decorated view function
    """
    def decorator(f: t.Callable) -> t.Callable:

        @wraps(f)
        def decorated_function(*args, **kwargs) -> Response:
            resp: Response | None = _verify_jwt(
                request,
                jwt_header_key=jwt_header_key,
                jwt_audience=jwt_audience,
                allowed_users=allowed_users,
                response_cls=response_cls,
                metric=metric
            )
            if resp is not None:
                return resp
            return f(*args, **kwargs)

        return decorated_function

    return decorator
