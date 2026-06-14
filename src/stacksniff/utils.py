"""Common utility functions for stacksniff.

Provides apex domain extraction and first-party domain comparison logic.
"""

from __future__ import annotations


def get_apex_domain(host: str) -> str:
    """Return the apex (registered) domain for *host*.

    Handles common two-part ccTLDs (e.g. co.uk, com.au) by returning the last
    three labels in that case; otherwise returns the last two labels.
    Also handles IPv4 addresses.

    Examples::

        get_apex_domain("v2.aiori.in")          -> "aiori.in"
        get_apex_domain("api.example.co.uk")    -> "example.co.uk"
        get_apex_domain("maps.googleapis.com")  -> "googleapis.com"
        get_apex_domain("127.0.0.1")            -> "127.0.0.1"
    """
    host = host.lower().split(":")[0]  # strip port
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return host
    if len(parts) >= 3:
        second_last = parts[-2]
        last = parts[-1]
        # Heuristic: short second-level (<=3 chars) + 2-char ccTLD -> 3-part apex
        if len(second_last) <= 3 and len(last) == 2:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_first_party(host1: str, host2: str) -> bool:
    """Return True if *host1* and *host2* share the same apex domain."""
    h1 = host1.lower().split(":")[0].removeprefix("www.")
    h2 = host2.lower().split(":")[0].removeprefix("www.")
    if h1 == h2:
        return True
    return get_apex_domain(h1) == get_apex_domain(h2)
