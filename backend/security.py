import hashlib
import secrets

import requests

MIN_PASSWORD_LENGTH = 12


def validate_password_strength(password):
    """NIST 800-63B-style password rule: length is the control that
    actually matters, not composition rules (forced digits/symbols push
    users toward predictable patterns like 'Password1!'). Returns
    (ok: bool, error: str | None)."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f'Password must be at least {MIN_PASSWORD_LENGTH} characters'
    return True, None


def check_password_pwned(password):
    """Best-effort breached-password check via the HIBP k-anonymity API --
    only the first 5 hex chars of the SHA-1 hash leave this server, so HIBP
    never sees the actual password. Returns True (breached), False (not
    found in the breach corpus), or None if the check couldn't be
    performed (network error/timeout/non-200). None is deliberately NOT
    treated as "breached" by callers -- this check must degrade gracefully
    rather than becoming an availability dependency for registration."""
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            timeout=3,
            headers={'Add-Padding': 'true'},
        )
        if resp.status_code != 200:
            return None
        for line in resp.text.splitlines():
            line_suffix, _, count = line.partition(':')
            if line_suffix.strip() == suffix and int(count or 0) > 0:
                return True
        return False
    except (requests.RequestException, ValueError):
        return None


def generate_reset_token():
    """Returns (raw_token, token_hash). Only token_hash is stored; the raw
    token is sent to the user (logged, not emailed -- see auth.py) and
    never persisted. SHA-256 (not a slow password hash) is appropriate here
    because the input is a 256-bit random token, not a human-chosen
    password -- there's no brute-force risk to defend against, only a fast
    equality lookup is needed."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    return raw_token, token_hash


def hash_reset_token(raw_token):
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
