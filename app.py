from flask import Flask, request, jsonify, redirect, url_for
import jwt
import os
import json
import secrets
import time
import base64
import urllib.parse
import requests
from datetime import datetime, timedelta
import redis

try:
    from dotenv import load_dotenv

    load_dotenv()
    print("Loaded .env file")
except ImportError:
    print("Failed to load .env file")
    pass

app = Flask(__name__)

# Flask secret
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY", b"random bytes representing flask secret key"
)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = (
    "true"  # !! Only in development environment.
)

# Redis setup
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    password=REDIS_PASSWORD,
    decode_responses=True,
)

# Discord OAuth config
DISCORD_CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_REDIRECT_URI = os.environ[
    "DISCORD_REDIRECT_URI"
]  # e.g., https://auth.yourclub.com/auth/discord/callback
DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")

# OAuth/OIDC provider config
ISSUER = os.getenv("ISSUER", "https://auth.yourclub.com")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "yourclub-services")

# RSA keys for RS256 JWT signing
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH", "public_key.pem")

# Load RSA keys
try:
    with open(PRIVATE_KEY_PATH, "r") as f:
        PRIVATE_KEY_PEM = f.read()
    with open(PUBLIC_KEY_PATH, "r") as f:
        PUBLIC_KEY_PEM = f.read()
except FileNotFoundError:
    print(
        "Warning: RSA keys not found. Generate them with: ssh-keygen -t rsa -b 2048 -m PEM"
    )
    PRIVATE_KEY_PEM = None
    PUBLIC_KEY_PEM = None

# Discord API endpoints
DISCORD_AUTH_URL = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_API_BASE = "https://discord.com/api"

# Role to subteam mapping (Discord role ID -> subteam name)
ROLE_TO_SUBTEAM = json.loads(os.getenv("ROLE_TO_SUBTEAM", "{}"))
# Example: {"123456789012345678": "software", "234567890123456789": "mechanical"}

# Registered OAuth clients (you can move this to Redis too if needed)
CLIENTS = json.loads(os.getenv("OAUTH_CLIENTS", "{}"))
# Example: {
#   "dfr-dashboard": {
#     "client_secret": "supersecret",
#     "redirect_uris": ["https://dashboard.yourclub.com/auth/callback"]
#   }
# }

# Redis key prefixes and TTLs
AUTH_REQUEST_PREFIX = "auth_req:"
AUTH_REQUEST_TTL = 600  # 10 minutes
AUTH_CODE_PREFIX = "auth_code:"
AUTH_CODE_TTL = 300  # 5 minutes


# ============================================================================
# Helper functions
# ============================================================================


def get_basic_auth():
    """Extract client_id and client_secret from Basic auth header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return None, None
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        client_id, client_secret = decoded.split(":", 1)
        return client_id, client_secret
    except Exception:
        return None, None


def store_auth_request(discord_state, data):
    """Store auth request in Redis with TTL."""
    key = f"{AUTH_REQUEST_PREFIX}{discord_state}"
    redis_client.setex(key, AUTH_REQUEST_TTL, json.dumps(data))


def get_auth_request(discord_state):
    """Retrieve and delete auth request from Redis."""
    key = f"{AUTH_REQUEST_PREFIX}{discord_state}"
    data = redis_client.get(key)
    if data:
        redis_client.delete(key)
        return json.loads(data)
    return None


def store_auth_code(code, data):
    """Store authorization code in Redis with TTL."""
    key = f"{AUTH_CODE_PREFIX}{code}"
    redis_client.setex(key, AUTH_CODE_TTL, json.dumps(data))


def get_auth_code(code):
    """Retrieve and delete authorization code from Redis (one-time use)."""
    key = f"{AUTH_CODE_PREFIX}{code}"
    data = redis_client.get(key)
    if data:
        redis_client.delete(key)
        return json.loads(data)
    return None


# Loading Role names from Discord API

def load_and_store_roles():
    """Load role names from Discord API for better logging (optional)."""
    def get_roles():
        if not DISCORD_GUILD_ID:
            return {}
        try:
            response = requests.get(
                f"{DISCORD_API_BASE}/guilds/{DISCORD_GUILD_ID}/roles",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            )
            if response.status_code != 200:
                print("Warning: Could not load roles from Discord")
                return {}
            roles = response.json()
            return {role["id"]: role["name"] for role in roles}
        except Exception as e:
            print(f"Warning: Could not load roles from Discord: {e}")
            return {}
    
    print("Loading roles...")
    roles = get_roles()
    # Store role names in Redis for logging purposes
    for role_id, role_name in roles.items():
        redis_client.hset("discord_roles", role_id, role_name)
    print(f"Loaded {len(roles)} roles from Discord")
load_and_store_roles()
# ============================================================================
# OAuth/OIDC Discovery Endpoints
# ============================================================================


@app.route("/.well-known/openid-configuration")
def openid_config():
    """OpenID Connect discovery endpoint."""
    return jsonify(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/oauth/authorize",
            "token_endpoint": f"{ISSUER}/oauth/token",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "jwks_uri": f"{ISSUER}/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "roles"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "claims_supported": [
                "sub",
                "discord_id",
                "discord_username",
                "roles",
                "subteams",
            ],
        }
    )


@app.route("/jwks.json")
def jwks():
    """JSON Web Key Set endpoint - exposes public key for JWT verification."""
    if not PUBLIC_KEY_PEM:
        return jsonify({"error": "JWKS not configured"}), 500

    # For a real implementation, you'd convert the PEM to JWK format
    # This is a simplified example - use a library like python-jose for production
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    import base64

    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_PEM.encode(), backend=default_backend()
    )

    numbers = public_key.public_numbers()

    def int_to_base64url(num):
        """Convert an integer to base64url encoding."""
        num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(num_bytes).rstrip(b"=").decode("utf-8")

    n = int_to_base64url(numbers.n)
    e = int_to_base64url(numbers.e)

    return jsonify(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "main-key-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": n,
                    "e": e,
                }
            ]
        }
    )


# ============================================================================
# OAuth Authorization Flow
# ============================================================================


@app.route("/oauth/authorize")
def oauth_authorize():
    """
    OAuth authorization endpoint.
    Client redirects here to start login flow.
    We validate the request, then redirect to Discord for authentication.
    """
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    response_type = request.args.get("response_type")
    scope = request.args.get("scope", "")
    state = request.args.get("state")

    # Validate client
    client = CLIENTS.get(client_id)
    if not client:
        return (
            jsonify(
                {"error": "unknown_client", "error_description": "Invalid client_id"}
            ),
            400,
        )

    if redirect_uri not in client["redirect_uris"]:
        return (
            jsonify(
                {
                    "error": "invalid_request",
                    "error_description": "Invalid redirect_uri",
                }
            ),
            400,
        )

    if response_type != "code":
        return jsonify({"error": "unsupported_response_type"}), 400

    # Create auth request and store in Redis
    discord_state = secrets.token_urlsafe(32)

    auth_req_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "created_at": int(time.time()),
    }

    store_auth_request(discord_state, auth_req_data)

    # Redirect to Discord OAuth
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": discord_state,
        "prompt": "consent",
    }

    discord_url = f"{DISCORD_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return redirect(discord_url)


@app.route("/auth/discord/callback")
def discord_callback():
    """
    Discord OAuth callback.
    Exchange Discord code for access token, fetch user info and roles,
    then redirect back to client with our own authorization code.
    """
    code = request.args.get("code")
    discord_state = request.args.get("state")
    error = request.args.get("error")

    if error:
        return (
            jsonify(
                {
                    "error": error,
                    "error_description": request.args.get("error_description"),
                }
            ),
            400,
        )

    # Retrieve auth request from Redis
    auth_req = get_auth_request(discord_state)
    if not auth_req:
        return (
            jsonify(
                {
                    "error": "invalid_state",
                    "error_description": "State parameter invalid or expired",
                }
            ),
            400,
        )

    # Exchange Discord code for access token
    token_data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        token_res = requests.post(DISCORD_TOKEN_URL, data=token_data, headers=headers)
        token_res.raise_for_status()
        tokens = token_res.json()
        access_token = tokens["access_token"]
    except Exception as e:
        return (
            jsonify({"error": "discord_token_error", "error_description": str(e)}),
            500,
        )

    # Get Discord user info
    try:
        user_res = requests.get(
            f"{DISCORD_API_BASE}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_res.raise_for_status()
        user = user_res.json()
        discord_user_id = user["id"]
        discord_username = user.get("username", "unknown")
        discord_name = user.get("global_name") or discord_username
        avatar_hash = user.get("avatar")
        email = user.get("email", "")
    except Exception as e:
        return (
            jsonify({"error": "discord_user_error", "error_description": str(e)}),
            500,
        )

    # Get guild member info and roles
    role_ids = []
    if DISCORD_GUILD_ID:
        try:
            member_res = requests.get(
                f"{DISCORD_API_BASE}/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}",
                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            )
            if member_res.status_code == 200:
                member = member_res.json()
                role_ids = member.get("roles", [])
                server_name = member.get("nick") or discord_username
        except Exception as e:
            print(f"Warning: Could not fetch guild member info: {e}")

    # Map roles to subteams
    subteams = list({ROLE_TO_SUBTEAM[r] for r in role_ids if r in ROLE_TO_SUBTEAM})

    # Create our own authorization code
    proxy_code = secrets.token_urlsafe(32)

    auth_code_data = {
        "client_id": auth_req["client_id"],
        "redirect_uri": auth_req["redirect_uri"],
        "scope": auth_req["scope"],
        "discord_id": discord_user_id,
        "discord_username": discord_username,
        "discord_name": server_name or discord_name,
        "avatar_hash": avatar_hash,
        "roles": role_ids,
        "subteams": subteams,
        "created_at": int(time.time()),
    }

    store_auth_code(proxy_code, auth_code_data)

    # Redirect back to client with our code and original state
    redirect_uri = auth_req["redirect_uri"]
    original_state = auth_req["state"]

    sep = "&" if "?" in redirect_uri else "?"
    params = {"code": proxy_code}
    if original_state:
        params["state"] = original_state

    final_url = f"{redirect_uri}{sep}{urllib.parse.urlencode(params)}"
    return redirect(final_url)


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    """
    OAuth token endpoint.
    Exchange authorization code for access_token and id_token (JWT).
    """
    grant_type = request.form.get("grant_type")

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")

    # Client authentication - support both Basic auth and client_secret_post
    client_id, client_secret = get_basic_auth()
    if not client_id:
        client_id = request.form.get("client_id")
        client_secret = request.form.get("client_secret")

    # Validate client
    client = CLIENTS.get(client_id)
    if not client or client["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    # Validate and consume authorization code
    auth_code = get_auth_code(code)
    if not auth_code:
        return (
            jsonify(
                {
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired code",
                }
            ),
            400,
        )

    if auth_code["client_id"] != client_id:
        return (
            jsonify(
                {
                    "error": "invalid_grant",
                    "error_description": "Code issued to different client",
                }
            ),
            400,
        )

    if auth_code["redirect_uri"] != redirect_uri:
        return (
            jsonify(
                {"error": "invalid_grant", "error_description": "Redirect URI mismatch"}
            ),
            400,
        )

    # Build JWT payload
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + 3600,  # 1 hour
        "sub": auth_code["discord_id"],
        "discord_id": auth_code["discord_id"],
        "discord_username": auth_code["discord_username"],
        "discord_name": auth_code["discord_name"],
        "avatar_hash": auth_code["avatar_hash"],
        "roles": auth_code["roles"],
        "subteams": auth_code["subteams"]
    }

    if not PRIVATE_KEY_PEM:
        return (
            jsonify(
                {
                    "error": "server_error",
                    "error_description": "JWT signing not configured",
                }
            ),
            500,
        )

    # Sign JWT with RS256
    token = jwt.encode(
        payload, PRIVATE_KEY_PEM, algorithm="RS256", headers={"kid": "main-key-1"}
    )

    # Return token response
    return jsonify(
        {
            "access_token": token,
            "id_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": auth_code["scope"],
        }
    )


@app.route("/userinfo")
def userinfo():
    """
    OAuth userinfo endpoint.
    Returns user claims from a valid access token.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing_token"}), 401

    token = auth_header.split(" ", 1)[1]

    if not PUBLIC_KEY_PEM:
        return (
            jsonify(
                {
                    "error": "server_error",
                    "error_description": "JWT verification not configured",
                }
            ),
            500,
        )

    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY_PEM,
            algorithms=["RS256"],
            audience=JWT_AUDIENCE,
            issuer=ISSUER,
        )
    except jwt.ExpiredSignatureError:
        return (
            jsonify({"error": "invalid_token", "error_description": "Token expired"}),
            401,
        )
    except jwt.InvalidTokenError as e:
        return jsonify({"error": "invalid_token", "error_description": str(e)}), 401

    # Return user info
    return jsonify(
        {
            "sub": payload["sub"],
            "discord_id": payload["discord_id"],
            "discord_username": payload["discord_username"],
            "discord_name": payload["discord_name"],
            "avatar_hash": payload["avatar_hash"],
            "avatar_url": f"https://cdn.discordapp.com/avatars/{payload['discord_id']}/{payload['avatar_hash']}.png" if payload["avatar_hash"] else None,
            "roles": {
                role_id: redis_client.hget("discord_roles", role_id) or "unknown"
                for role_id in payload["roles"]
            },
            "subteams": payload["subteams"],
        }
    )


# ============================================================================
# Health check
# ============================================================================


@app.route("/")
def home():
    """Health check endpoint."""
    return (
        jsonify(
            {
                "message": "OAuth/OIDC server online",
                "issuer": ISSUER,
                "discovery": f"{ISSUER}/.well-known/openid-configuration",
            }
        ),
        200,
    )


if __name__ == "__main__":
    app.run(debug=True)
