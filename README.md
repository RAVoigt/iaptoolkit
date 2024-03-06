# IAP Toolkit

A library of utils to ease programmatic authentication with Google IAP (and ideally other IAPs in future).

## Configuration & Env Vars

| Env Var | Default | Type | Description|
|---|---|---|---|
|`KVC_LOG_FORMAT`|`"%(asctime)s - [%(levelname)s] - %(name)s - %(message)s"`|String|Sets log format for internal logger|
|`KVC_LOG_DATEFMT`|`"%Y-%m-%d %H:%M:%S"`|String|Sets log datetime format for internal logger|
|`IAPTOOLKIT_USE_AUTH_HEADER`|`False`|Boolean|If False, only adds Google IAP auth tokens to the `Proxy-Authorization` header. If True, adds tokens in the `Authorization` header if available/unused, falling back to the `Proxy-Authorization` header if needed. |
|`IAPTOOLKIT_PERSISTENT_DATASTORE_ENABLED`|`False`|Boolean|If true, the TOML-backed datastore for tokens is enabled.|
|`IAPTOOLKIT_PERSISTENT_DATASTORE_PATH`|`"~/.iaptoolkit"`|String|Path to dir where TOML-backed datastore|
|`IAPTOOLKIT_PERSISTENT_DATASTORE_USERNAME`|`"user.toml"`|String|Filename for TOML-backed datastore|
|`IAPTOOLKIT_CONFIG_VERSION`|`False`|Boolean|(Unused) Schema version for token storage|
|`GOOGLE_IAP_CLIENT_ID`|None|String|#TODO|
|`GOOGLE_CLIENT_ID`|None|String|#TODO|
|`GOOGLE_CLIENT_SECRET`|None|String|#TODO|

## Disclaimer

This project is not affiliated with Google. No trademark infringement intended.
