"""Security primitives for privacy-preserving password exposure checks.

This module implements helper functions used by the k-anonymity workflow of the
Have I Been Pwned (HIBP) password range API. The design goal is to keep these
functions pure and deterministic, so they are easy to test and safe to reuse.
"""

from __future__ import annotations

import hashlib

SHA1_HASH_LENGTH = 40
PREFIX_LENGTH = 5
SUFFIX_LENGTH = SHA1_HASH_LENGTH - PREFIX_LENGTH


def sha1_upper(text: str) -> str:
    """Return the uppercase SHA-1 hex digest for ``text``.

    Why uppercase: HIBP range responses and common tooling conventions use
    uppercase hex digests, so normalizing here avoids repeated transformations.
    """

    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def extract_k_anonymity_prefix(sha1_hash: str) -> str:
    """Return the first 5 characters of an uppercase SHA-1 hash.

    The 5-character prefix is the only password-derived value transmitted to HIBP,
    which preserves user privacy via k-anonymity.
    """

    normalized = sha1_hash.strip().upper()
    if len(normalized) != SHA1_HASH_LENGTH:
        raise ValueError("SHA-1 hash must be exactly 40 hex characters.")
    return normalized[:PREFIX_LENGTH]


def extract_k_anonymity_suffix(sha1_hash: str) -> str:
    """Return the trailing 35 characters of an uppercase SHA-1 hash.

    The suffix is compared locally against HIBP response lines so full hashes are
    never transmitted externally.
    """

    normalized = sha1_hash.strip().upper()
    if len(normalized) != SHA1_HASH_LENGTH:
        raise ValueError("SHA-1 hash must be exactly 40 hex characters.")
    return normalized[PREFIX_LENGTH:]


def hash_and_split_for_hibp(password: str) -> tuple[str, str]:
    """Hash ``password`` and return its HIBP k-anonymity (prefix, suffix) tuple.

    This function is the canonical one-step utility for callers that need both
    parts for range query lookups and local suffix matching.
    """

    digest = sha1_upper(password)
    return extract_k_anonymity_prefix(digest), extract_k_anonymity_suffix(digest)


def hash_user_identifier(identifier: str) -> str:
    """Return a stable SHA-256 hex digest for user identifier pseudonymization."""

    return hashlib.sha256(identifier.strip().lower().encode("utf-8")).hexdigest()
