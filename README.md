# DevChat Kong Keycloak JWT Verify Plugin for Kong

This is a custom Kong plugin for verifying JWT access tokens issued by Keycloak using the JWKS (JSON Web Key Set) endpoint. It provides a secure and efficient way to authenticate requests in an API Gateway setup, leveraging caching of JWKS and PEM certificates to minimize network overhead. The plugin injects user information into the request headers for downstream services to utilize.

## About this Plugin

This plugin was created as part of the DevChat (my study project) project to centralize and optimize JWT validation in Kong. It retrieves signing keys from a Keycloak JWKS endpoint, converts them to PEM certificates, and caches them for signature verification. Developed to solve the practical problem of validating JWT access tokens issued by Keycloak in a Kong API gateway environment, this plugin enhances security and performance by offloading token validation from backend services.

It ensures:
- Tokens are signed with valid keys (kid matching),
- Claims like exp, iat, azp, and iss are verified,
- PEM keys are cached per kid for performance,
- User identity is propagated via headers,
- Standardized error responses are returned when validation fails.

<br>

> This repository/module is part of the [DevChat Monorepo](https://github.com/bccalegari/dev-chat-monorepo)

## Usecase

In a typical scenario, the frontend application uses OAuth2 with OpenID Connect to authenticate users and obtain access tokens from Keycloak. These tokens are then sent in requests to backend APIs.

This plugin is used in Kong as an API gateway to protect those backend services. Kong validates the JWT access tokens by verifying their signature using the public keys obtained from Keycloak's JWKS endpoint, ensuring they are active and valid. Upon successful validation, the plugin injects relevant user information into the request headers, such as `X-User-Id` and `X-User-Name`. This allows backend services to identify the user without needing to handle token validation themselves.

This setup helps centralize security at the gateway layer, offloading token verification from the backend services and maintaining a clean, scalable architecture.

## Features

- Directly verifies JWT signatures using Keycloak's JWKS endpoint
- Validates token expiry (exp) and issued-at (iat) claims
- Supports configurable issuer (iss), and authorized party (azp) claim
- Propagates user information (`sub`, `preferred_username`) as request headers  
- Caches JWKS keys for improved performance
- Returns detailed and standardized error responses  
- Clean logging for troubleshooting  

## Dependencies

Requires Kong 3 and the following Lua libraries:
- `lua-resty-jwt`: For JWT parsing and validation

## Installation

Copy the plugin directory into your Kong’s custom plugins folder, or package it accordingly.

```bash
cp -r dev-chat/kong/plugins/dev-chat-kong-keycloak-jwt-verify /path/to/kong/plugins/
```

Example for Docker:

```bash
docker cp dev-chat/kong/plugins/dev-chat-kong-keycloak-jwt-verify <kong-container-name>:/usr/local/share/lua/5.1/kong/plugins/
```

After copying the plugin, ensure it is recognized by Kong by adding it to the `KONG_PLUGINS` environment variable in your Kong configuration:

```bash
KONG_PLUGINS=bundled,dev-chat-kong-keycloak-jwt-verify
```

Then, add the plugin to your Kong configuration:

```yaml
plugins:
  - name: dev-chat-kong-keycloak-jwt-verify
    config:
      jwks_url: "<your-host>/realms/<your-realm>/protocol/openid-connect/certs"
      client_id: "<your-client-id>"
      issuer: "<your-host>/realms/<your-realm>"
      jwks_cache_ttl: "<your-cache-ttl-in-seconds>"
      pem_cache_ttl: "<your-cache-ttl-in-seconds>"
```

## Configuration
| Property                 | Type    | Required | Default | Description                                                 |
| ------------------------ | ------- | -------- | ------- | ----------------------------------------------------------- |
| `jwks_url`             | string  | yes      | —       | URL of the Keycloak JWKS endpoint                           |
| `client_id`              | string  | yes      | —       | Client ID to validate the token against                      |
| `issuer`                 | string  | no       | —       | Expected issuer of the JWT token                            |
| `jwks_cache_ttl`         | integer | no       | 3600    | Time to live for JWKS cache in seconds                      |
| `pem_cache_ttl`          | integer | no       | 600    | Time to live for PEM cache in seconds                       |

## Usage
Attach the plugin to your service or route in Kong.
When a request includes an `Authorization` header with a Bearer token, the plugin will:

1. Extract the token from the `Authorization` header.
2. Decode the JWT and extract the `kid` (Key ID).
3. Fetch the JWKS from the configured `jwks_url` (and cache it based on `jwks_cache_ttl`).
4. Find the public key corresponding to the `kid` in the JWKS and convert it to PEM format (caching it based on `pem_cache_ttl`).
5. Verify the JWT's signature using the retrieved public key.
6. Validate standard claims such as `exp` (expiration), `iat` (issued at), and optionally `iss` (issuer), and `azp` (authorized party) based on the plugin's internal configuration.
7. If the token is valid, it will inject user information headers into the request.
8. If the token is missing, invalid, or expired, it will return a detailed error response.
9. If the signature verification fails, the required key is not found, or the token is invalid, missing or expired, it will return a detailed error response.
10. On success, it adds headers:
   - `X-User-Id`: The user ID from the token (`sub` claim).
   - `X-User-Name`: The username from the token (`preferred_username` claim).

Upstream services can then use these headers to identify the user.

## Error Handling
If the token is invalid, signature verification fails or any other error occurs, the plugin will return a standardized JSON error response with the following structure:

```json
{
  "timestamp": <timestamp>,
  "error": "<error-type>",
  "message": "<detailed-error-message>"
}
```

## Troubleshooting
For debugging, you can enable Kong's debug logging to see detailed logs of the plugin's operations. This can help identify issues with JWKS retrieval, PEM conversion, or JWT validation.

```bash
KONG_LOG_LEVEL=debug
```

## Contributing
Contributions and issues are welcome! Please open GitHub issues or pull requests.

## License
This plugin is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.

----

Built with ❤️ by Bruno Calegari