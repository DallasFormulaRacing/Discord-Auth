# Discord-backed OAuth/OIDC Provider

A standard OAuth 2.0 / OpenID Connect provider that uses Discord for authentication and role-based authorization.

## Features

- ✅ Full OAuth 2.0 Authorization Code flow
- ✅ OpenID Connect discovery endpoint
- ✅ RS256 JWT signing with JWKS endpoint
- ✅ Discord role → subteam mapping
- ✅ Redis-backed storage for auth codes and requests
- ✅ Standard endpoints for easy integration

## Architecture

```
Client App (Dashboard) 
    ↓ redirects to
OAuth Provider (this app)
    ↓ redirects to
Discord OAuth
    ↓ callback with user + roles
OAuth Provider
    ↓ issues JWT with subteams
Client App
```

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate RSA Keys

Generate an RSA keypair for JWT signing:

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### 3. Start Redis

```bash
# Using Docker
docker run -d -p 6379:6379 redis:latest

# Or install locally
# macOS: brew install redis && brew services start redis
# Ubuntu: sudo apt install redis-server && sudo systemctl start redis
```

### 4. Configure Environment

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Required configuration:

- **Discord OAuth App**: Create at https://discord.com/developers/applications
  - Set `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`
  - Add redirect URI: `https://auth.yourclub.com/auth/discord/callback`
  
- **Discord Bot**: Create a bot in the same app
  - Set `DISCORD_BOT_TOKEN`
  - Enable "Server Members Intent"
  - Invite to your guild with `guilds.members.read` scope
  
- **Guild & Roles**: 
  - Set `DISCORD_GUILD_ID` to your Discord server ID
  - Map role IDs to subteam names in `ROLE_TO_SUBTEAM`

- **OAuth Clients**:
  - Register each dashboard/app in `OAUTH_CLIENTS`
  - Format: `{"client-id": {"client_secret": "secret", "redirect_uris": ["https://..."]}}`

### 5. Run the Server

```bash
python app.py
```

## Endpoints

### Public OAuth/OIDC Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/openid-configuration` | GET | OpenID Connect discovery |
| `/jwks.json` | GET | Public key for JWT verification |
| `/oauth/authorize` | GET | Start OAuth flow |
| `/oauth/token` | POST | Exchange code for tokens |
| `/userinfo` | GET | Get user info from token |

### Internal Endpoint

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/discord/callback` | GET | Discord OAuth callback |

## Usage Example

### 1. Client Initiates Login

Redirect user to:

```
GET https://auth.yourclub.com/oauth/authorize
  ?client_id=dfr-dashboard
  &redirect_uri=https://dashboard.yourclub.com/auth/callback
  &response_type=code
  &scope=openid profile roles
  &state=random_state_123
```

### 2. User Authenticates with Discord

The OAuth provider redirects to Discord, user logs in and authorizes.

### 3. Callback with Authorization Code

User is redirected back to your client:

```
GET https://dashboard.yourclub.com/auth/callback
  ?code=AUTH_CODE_HERE
  &state=random_state_123
```

### 4. Exchange Code for Tokens

```bash
curl -X POST https://auth.yourclub.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "dfr-dashboard:supersecret" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=https://dashboard.yourclub.com/auth/callback"
```

Response:

```json
{
  "access_token": "eyJhbGc...",
  "id_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile roles"
}
```

### 5. Decode JWT

The JWT contains:

```json
{
  "iss": "https://auth.yourclub.com",
  "aud": "yourclub-services",
  "sub": "123456789",
  "discord_id": "123456789",
  "discord_username": "user#1234",
  "roles": ["123456789012345678", "234567890123456789"],
  "subteams": ["software", "mechanical"],
  "iat": 1700000000,
  "exp": 1700003600
}
```

### 6. Verify JWT

Any service can verify the JWT using the public key from `/jwks.json`:

```python
import jwt
import requests

# Fetch JWKS
jwks_res = requests.get("https://auth.yourclub.com/jwks.json")
jwks = jwks_res.json()

# Verify token (most libraries handle JWKS automatically)
payload = jwt.decode(
    token,
    jwks,
    algorithms=["RS256"],
    audience="yourclub-services",
    issuer="https://auth.yourclub.com"
)

print(f"User: {payload['discord_username']}")
print(f"Subteams: {payload['subteams']}")
```

## Storage

### Redis Keys

- `auth_req:<discord_state>` - Auth request data (TTL: 10 min)
- `auth_code:<code>` - Authorization code data (TTL: 5 min)

### Key Rotation

To rotate the JWT signing key:

1. Generate new keypair
2. Add to JWKS with new `kid`
3. Update signing to use new `kid`
4. Keep old key in JWKS for verification during transition
5. Remove old key after all tokens expire

## Security Notes

- ⚠️ **HTTPS Required**: Run behind reverse proxy with TLS in production
- ⚠️ **Secure Secrets**: Use strong `client_secret` values
- ⚠️ **Redis Security**: Enable Redis AUTH in production
- ⚠️ **Rate Limiting**: Add rate limiting to prevent abuse
- ⚠️ **OAUTHLIB_INSECURE_TRANSPORT**: Remove in production (only for dev)

## Integration with Other Services

Any service that supports OAuth 2.0 / OIDC can integrate:

1. Configure the service with:
   - Discovery URL: `https://auth.yourclub.com/.well-known/openid-configuration`
   - Or manually set authorization/token/userinfo endpoints
   
2. Register the service as a client in `OAUTH_CLIENTS`

3. Service will receive JWTs with `subteams` claim for authorization

## Troubleshooting

### "Invalid state" error

- Check Redis is running and accessible
- Verify `AUTH_REQUEST_TTL` isn't too short
- Check system time is synchronized

### "Invalid client" error

- Verify client is registered in `OAUTH_CLIENTS`
- Check `client_secret` matches
- Ensure `redirect_uri` is in allowed list

### JWT verification fails

- Confirm public key in `/jwks.json` matches private key
- Check token hasn't expired
- Verify `aud` and `iss` claims match configuration

## License

MIT
