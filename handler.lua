local jwt_decoder = require "resty.jwt"
local jwt_validators = require "resty.jwt-validators"
local http = require "resty.http"
local cjson = require "cjson.safe"
local kong = kong
local pkey = require "resty.openssl.pkey"
local ngx_base64 = require "ngx.base64"

local plugin = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

local function fetch_jwks(jwks_url)
  kong.log.info("Fetching JWKS from URL: ", jwks_url)
  local httpc = http.new()
  httpc:set_keepalive(60000, 100)
  
  local res, err = httpc:request_uri(jwks_url, { 
    method = "GET", 
    ssl_verify = false
  })
  if not res or res.status ~= 200 then
    kong.log.err("Failed to fetch JWKS: ", err or res.status)
    return nil
  end

  kong.log.debug("JWKS response: ", res.body)

  local body, err = cjson.decode(res.body)
  if not body or not body.keys then
    kong.log.err("Invalid JWKS response: ", err)
    return nil
  end

  return body.keys
end

local function get_signing_keys(conf)
  local cache_key = "devchat_jwks:" .. conf.jwks_url
  local opts = conf.jwks_cache_ttl and { ttl = conf.jwks_cache_ttl } or nil
  kong.log.debug("Retrieving keys from cache with key: ", cache_key)

  local keys, err = kong.cache:get(cache_key, opts, fetch_jwks, conf.jwks_url)
  if err then
    kong.log.err("Error getting JWKS from cache: ", err)
    return nil
  end

  kong.log.info("JWKS keys successfully retrieved (cached or fresh)")
  return keys
end

local function find_key(keys, kid)
  kong.log.debug("Looking for key with kid: ", kid)
  for _, key in ipairs(keys) do
    if key.kid == kid then
      kong.log.debug("Found matching key for kid: ", kid)
      return key
    end
  end
  kong.log.warn("No matching key found for kid: ", kid)
  return nil
end

local function get_pem_from_cache(kid)
  local cache_key = "devchat_pem:" .. kid
  local pem, err = kong.cache:get(cache_key)

  kong.log.debug("Retrieving PEM from cache with key: ", cache_key)
  if pem then
    kong.log.debug("PEM found in cache for kid: ", kid)
  end

  if err then
    kong.log.err("Error caching PEM for kid ", kid, ": ", err)
    return nil
  end
  
  return pem
end

local function jwk_to_pem(jwk)
  kong.log.debug("Converting JWK x5c to PEM")

  if jwk.kty ~= "RSA" then
    kong.log.err("Unsupported key type: ", jwk.kty)
    return nil
  end

  if not jwk.x5c or #jwk.x5c == 0 then
    kong.log.err("Missing x5c field in JWK")
    return nil
  end

  local cert_base64 = jwk.x5c[1]

  local formatted_cert = cert_base64:gsub("(.{64})", "%1\n")
  local pem = "-----BEGIN CERTIFICATE-----\n" .. formatted_cert .. "\n-----END CERTIFICATE-----"

  kong.log.debug("PEM generated from x5c: ", pem)
  return pem
end

function plugin:access(conf)
  local auth_header = kong.request.get_header("Authorization")
  if not auth_header or type(auth_header) ~= "string" or not auth_header:find("Bearer ") then
    kong.log.warn("Authorization header is missing or invalid")
    return kong.response.exit(401, { 
      timestamp = ngx.time(),
      error = "Unauthorized",
      message = "Authorization header is missing or invalid, please provide a valid Bearer token in the Authorization header with the format 'Bearer <token>'"
    })
  end

  local token = auth_header:match("Bearer%s+(.+)")
  if not token then
    kong.log.warn("Bearer token not found in Authorization header")
    return kong.response.exit(401, { 
      timestamp = ngx.time(),
      error = "Unauthorized",
      message = "Bearer token not found in Authorization header"
    })
  end

  kong.log.debug("Decoding token...")
  local decoded_token = jwt_decoder:load_jwt(token)
  if not decoded_token.valid then
    kong.log.warn("Invalid JWT: ", decoded_token.reason or "unknown reason")
    return kong.response.exit(401, { 
      timestamp = ngx.time(),
      error = "Unauthorized",
      message = "Invalid JWT: " .. (decoded_token.reason or "unknown reason, please activate debug mode to see more details"),
    })
  end

  kong.log.debug("Token decoded successfully")
  kong.log.debug("JWT token decoded: ", cjson.encode(decoded_token))

  local kid = decoded_token.header.kid
  if not kid then
    kong.log.warn("Missing 'kid' in JWT header")
    return kong.response.exit(401, { 
      timestamp = ngx.time(),
      error = "Unauthorized",
      message = "Missing 'kid' in JWT header"
    })
  end

  local pem_key = get_pem_from_cache(kid)
  local hasPemOnCache = pem_key ~= nil
  if not pem_key then
    local keys = get_signing_keys(conf)

    if not keys then
      kong.log.err("Could not retrieve JWKS keys")
      return kong.response.exit(500, {
        timestamp = ngx.time(),
        error = "Internal Server Error",
        message = "Could not retrieve JWKS keys"
      })
    end

    local key = find_key(keys, kid)
    if not key then
      return kong.response.exit(401, {
        timestamp = ngx.time(),
        error = "Unauthorized",
        message = "No matching key found for 'kid'"
      })
    end

    kong.log.debug("Starting JWT signature verification")
    pem_key = jwk_to_pem(key)
    if not pem_key then
      kong.log.err("Failed to convert JWK to PEM")
      return kong.response.exit(500, {
        timestamp = ngx.time(),
        error = "Internal Server Error",
        message = "Failed to process public key"
      })

    end
  end

  local claim_specs = {
    exp = jwt_validators.is_not_expired(),
    iat = jwt_validators.is_not_before()
  }

  if conf.client_id then
    claim_specs.azp = jwt_validators.equals(conf.client_id)
  end
  
  if conf.issuer then
    claim_specs.iss = jwt_validators.equals(conf.issuer)
  end
  
  local verified_token = jwt_decoder:verify_jwt_obj(pem_key, decoded_token, claim_specs)
  if not verified_token or not verified_token.verified then
    kong.log.warn("JWT signature verification failed")
    kong.log.debug("Verification details: ", cjson.encode(verified_token))

    return kong.response.exit(401, {
      timestamp = ngx.time(),
      error = "Unauthorized",
      message = "JWT signature verification failed: " .. (verified_token.reason or "unknown reason, please activate debug mode to see more details"),
    })
  end

  if not hasPemOnCache then
    kong.log.debug("Caching PEM key for kid: ", kid)
    local opts = conf.pem_cache_ttl and { ttl = conf.pem_cache_ttl } or nil
    kong.cache:get("devchat_pem:" .. kid, opts, function()
      return pem_key
    end)
    kong.log.debug("PEM key cached successfully with ttl: ", conf.pem_cache_ttl)
  end

  kong.log.info("JWT signature verified successfully")
  kong.log.info("Token is valid. Injecting headers")
  kong.service.request.set_header("X-User", decoded_token.payload.preferred_username or "")
  kong.service.request.set_header("X-User-ID", decoded_token.payload.sub or "")

  ngx.ctx.auth_success = true
end

return plugin