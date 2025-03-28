from enum import StrEnum

class JWT_Event(StrEnum):
    SUCCESS = "success"
    FAIL_NO_HEADER = "fail_no_header"
    FAIL_INVALID_JWT = "fail_invalid"
    FAIL_NO_EMAIL = "fail_no_email"
    FAIL_WRONG_USER = "fail_wrong_user"
    FAIL_WRONG_AUDIENCE = "fail_wrong_audience"