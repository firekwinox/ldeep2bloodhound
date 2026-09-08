"""Small helpers: GUID/SID normalization, DN parsing, timestamp conversion."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_GUID_BRACES_RE = re.compile(r"^\{?([0-9a-fA-F-]{36})\}?$")


def norm_guid(guid: str) -> str:
    """Normalize an objectGUID value (ldeep gives "{xxxx-...}") to upper,
    no-braces form, matching BloodHound's ObjectIdentifier convention for
    GUID-identified objects (OU/GPO/Container/CertTemplate/...)."""
    if not guid:
        return guid
    m = _GUID_BRACES_RE.match(guid.strip())
    return (m.group(1) if m else guid.strip("{}")).upper()


def norm_sid(sid: str) -> str:
    if not sid:
        return sid
    return sid.strip().upper()


def dn_upper(dn: str) -> str:
    return dn.strip().upper() if dn else dn


def parent_dn(dn: str) -> str | None:
    """Return the DN of the immediate parent container, or None for a root DN
    (e.g. "DC=example,DC=com" has no parent within the same tree)."""
    if not dn:
        return None
    parts = split_dn(dn)
    if len(parts) <= 1:
        return None
    return ",".join(parts[1:])


def split_dn(dn: str) -> list[str]:
    """Split a DN into its RDN components, respecting escaped commas."""
    parts = []
    buf = []
    escape = False
    for ch in dn:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == ",":
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def rdn_value(dn: str) -> str:
    """Return the value part of the leaf RDN of a DN, e.g.
    "CN=foo,OU=bar,DC=x" -> "foo"."""
    if not dn:
        return dn
    leaf = split_dn(dn)[0]
    if "=" in leaf:
        return leaf.split("=", 1)[1]
    return leaf


# Windows FILETIME epoch (1601-01-01) as a Unix timestamp offset, in seconds.
_FILETIME_NEVER_ISO_PREFIX = "1601-01-01"
_FILETIME_MAX_ISO_PREFIX = "9999-12-31"


def iso_to_epoch(value, zero_is_never: bool = True) -> int:
    """Convert one of ldeep's ISO8601 datetime strings (as produced for
    FILETIME_FIELDS/DATETIME_FIELDS) into a Unix epoch int, the convention
    BloodHound's Properties dict uses for all date fields.

    The AD "never" sentinel (1601-01-01, FILETIME 0) and the "never expires"
    sentinel (9999-12-31) both become -1, matching SharpHound's behaviour for
    lastlogon/pwdlastset/accountexpires-style fields.
    """
    if not value:
        return -1 if zero_is_never else 0
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value)
    if s.startswith(_FILETIME_NEVER_ISO_PREFIX) or s.startswith(_FILETIME_MAX_ISO_PREFIX):
        return -1 if zero_is_never else 0
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return -1 if zero_is_never else 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def uac_has(uac_str: str, flag_name: str) -> bool:
    """ldeep decodes userAccountControl/groupType/msDS-SupportedEncryptionTypes
    into a "FLAG_A | FLAG_B" string. Test membership by exact token match so
    e.g. "ACCOUNTDISABLE" doesn't false-positive on a flag containing it as a
    substring."""
    if not uac_str:
        return False
    tokens = {t.strip() for t in str(uac_str).split("|")}
    return flag_name in tokens
