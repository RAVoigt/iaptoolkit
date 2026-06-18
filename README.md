# IAP Toolkit

A library of utils to ease programmatic authentication with Google IAP (and ideally other IAPs in future).

# PyPi
https://pypi.org/project/iaptoolkit/

# Installation
### With Poetry:
`poetry add iaptoolkit`

### With pip:
`pip install iaptoolkit`

## Quick Start / Example Usage

```python
import requests

from iaptoolkit import IAPToolkit

iaptk = IAPToolkit(google_iap_client_id="EXAMPLE_ID_123456789ABCDEF")
allowed_domains = ["example.com", ]


# Example #1 - Combined Calls
def example1(url: str):
    headers = dict()
    result = iaptk.check_url_and_add_token_header(
        url=url,
        request_headers=headers,
        iap_audience="some_iap_client_id_string" # OAuth Client ID for the IAP-protected resource as 'audience'
        valid_domains=allowed_domains
    )
    # result.token_added (bool) indicates if the token was added, depending on whether or not URL was valid
    # headers dict now contains the appropriate Bearer Token header for Google IAP

    # Make HTTP GET request with requests lib, with our headers containing bearer token to auth with IAP
    response = requests.request("GET", url, headers=headers)


# Example #2 - Separate Calls - Functionally the same as Example 1 but more flexibility in URL validation
def example2(url: str):
    is_url_safe: bool = iaptk.is_url_safe_for_token(url=url, valid_domains=valid_domains)

    if not is_url_safe:
        raise ExampleBadURLException("This URL isn't safe to send token headers to!")

    headers = dict()
    token_is_fresh: bool = iaptk.get_token_and_add_to_headers(
        request_headers=headers,
        iap_audience="some_iap_client_id_string" # OAuth Client ID for the IAP-protected resource as 'audience'
    )
    # token_is_fresh indicates if token was newly retrieved (True), or if a cached token was reused (False)
    # headers dict now contains the appropriate Bearer Token header for Google IAP

    # Make HTTP GET request with requests lib, with our headers containing bearer token to auth with IAP
    response = requests.request("GET", url, headers=headers)

# Example #3 - Service Account JWT (instead of OIDC Token)
def example3(url: str):
    headers = dict()
    result = iaptk.check_url_and_add_jwt_header(
        url=url,
        request_headers=headers,
        service_account_email="service-account@PROJECT_ID.iam.gserviceaccount.com",
        url_audience="https://some-iap-protected.resource/path",
        valid_domains=allowed_domains
    )
    # result.token_added (bool) indicates if the token was added, depending on whether or not URL was valid
    # headers dict now contains the appropriate Bearer JWT header for Google IAP

    # Make HTTP GET request with requests lib, with our headers containing bearer token to auth with IAP
    response = requests.request("GET", url, headers=headers)

# Example #4 - Separate Calls - Service Account JWT - Functionally the same as Example 3 but more flexibility in URL validation
def example4(url: str):
    is_url_safe: bool = iaptk.is_url_safe_for_token(url=url, valid_domains=valid_domains)

    if not is_url_safe:
        raise ExampleBadURLException("This URL isn't safe to send token headers to!")

    headers = dict()
    token_is_fresh: bool = iaptk.get_jwt_and_add_to_headers(
        request_headers=headers,
        service_account_email="service-account@PROJECT_ID.iam.gserviceaccount.com",
        url_audience="https://some-iap-protected.resource/path"
    )
    # token_is_fresh indicates if token was newly retrieved (True), or if a cached token was reused (False)
    # headers dict now contains the appropriate Bearer Token header for Google IAP

    # Make HTTP GET request with requests lib, with our headers containing bearer token to auth with IAP
    response = requests.request("GET", url, headers=headers)
```

## Disclaimer

This project is not affiliated with Google. No trademark infringement intended.
