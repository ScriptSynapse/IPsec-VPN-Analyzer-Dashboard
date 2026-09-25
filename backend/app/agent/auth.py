"""API key generation/verification for monitoring agents.

Only a SHA-256 hash of the key is ever persisted (AgentRecord.api_key_hash).
The plaintext key is generated here, returned to the caller exactly once at
registration time, and is not recoverable after that -- the same model as
a GitHub personal access token.
"""

import hashlib
import hmac
import secrets

_KEY_BYTES = 32  # 256 bits


def generate_api_key() -> str:
    return secrets.token_urlsafe(_KEY_BYTES)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_api_key(key: str, key_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(key), key_hash)
