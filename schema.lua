local typedefs = require "kong.db.schema.typedefs"

return {
  name = "dev-chat-kong-keycloak-jwt-verify",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          {
            jwks_url = typedefs.url {
              required = true,
              description = "URL to fetch JWKS keys for verifying JWTs",
            },
          },
          {
            issuer = {
              type = "string",
              required = false,
              description = "Expected 'iss' (issuer) claim in the JWT",
            },
          },
          {
            client_id = {
              type = "string",
              required = false,
              description = "Expected 'azp' (authorized party) claim in the JWT",
            },
          },
          {
            jwks_cache_ttl = {
              type = "number",
              required = false,
              default = 3600,
              description = "Time to live for cached JWKS keys in seconds, defaults to 600 seconds",
            },
          },
          {
            pem_cache_ttl = {
              type = "number",
              required = false,
              default = 600,
              description = "Time to live for cached PEM keys in seconds, defaults to 600 seconds",
            },
          }
        },
      },
    },
  },
}