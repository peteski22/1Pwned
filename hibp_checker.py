"""Handles all interactions with the HaveIBeenPwned (HIBP) Pwned Passwords API."""

import hashlib

import requests
from hashed_password import HashedPassword

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"  # HIBP API URL template
USER_AGENT = "1Password-Pwned-Check/1.0"  # User-Agent header for HIBP API
TIMEOUT = 15  # requests timeout


class HIBPError(Exception):
    """Base exception for HIBP API errors."""

    pass


class HIBPRateLimitError(HIBPError):
    """Raised for 429 status codes."""

    pass


def hash_password(password: str) -> HashedPassword:
    """Hashes a password with SHA-1 and splits it into a HIBP prefix and suffix.

    Args:
        password: The plaintext password to hash.

    Returns:
        A HashedPassword object containing the 5-character prefix and the
        35-character suffix.
    """
    h = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]

    return HashedPassword(prefix=prefix, suffix=suffix)


def find_suffix_in_response(response_text: str, suffix_to_find: str) -> int:
    """Parses the raw HIBP API text response to find the count for a specific suffix.

    Args:
        response_text: The raw text response from the HIBP API, where each line is formatted as 'SUFFIX:COUNT'.
        suffix_to_find: The specific hash suffix (case-sensitive) to search for within the response.

    Returns:
        The pwned count as an integer if the suffix is found, or 0 if it
        is not found or lines are malformed.
    """
    for line in response_text.splitlines():
        try:
            suffix, count_str = line.split(":")
            if suffix == suffix_to_find:
                return int(count_str)
        except ValueError:
            # Ignore malformed lines
            pass
    return 0


def fetch_hibp_suffixes(prefix: str) -> str:
    """Fetches the list of pwned password suffixes for a given 5-char prefix.

    Args:
        prefix: The 5-character SHA-1 hash PREFIX to send to the HIBP API.

    Returns:
        The raw text response from the HIBP API.

    Raises:
        HIBPRateLimitError: If the API returns a 429 status code.
        HIBPError: For any other non-200 status code or a request-level
            exception.
    """
    url = HIBP_RANGE_URL.format(prefix)
    headers = {"User-Agent": USER_AGENT}

    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)

        if r.status_code == 429:
            raise HIBPRateLimitError("Rate limited by HIBP (429).")

        r.raise_for_status()  # Raises HTTPError for 4xx/5xx

        return r.text

    except requests.RequestException as e:
        raise HIBPError(f"HIBP API request failed: {e}") from e


def check_pwned_hash(hashed_pass: HashedPassword) -> int:
    """Gets the pwned count for a given HashedPassword.

    This function composes fetch_hibp_suffixes and find_suffix_in_response.

    Args:
        hashed_pass: The HashedPassword object containing the prefix and suffix
            to check against the HIBP API.

    Returns:
        The pwned count for the password.

    Raises:
        HIBPRateLimitError: (Propagated) If the API returns a 429 status.
        HIBPError: (Propagated) For other request failures.
    """
    response_text = fetch_hibp_suffixes(hashed_pass.prefix)

    count = find_suffix_in_response(response_text, hashed_pass.suffix)

    return count
