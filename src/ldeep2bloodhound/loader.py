"""Loads an ldeep dump directory into an in-memory, indexed object model."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from . import constants as C
from .sidutils import dn_upper, norm_guid, norm_sid

log = logging.getLogger(__name__)

# The dump files this loader reads. Prefix detection anchors on these exact
# names rather than splitting a filename on its first "__", so a prefix that
# itself contains "__" still resolves correctly.
DUMP_FILES = ("users_all", "machines", "groups", "gpo", "fsp", "domain_policy", "ou", "trusts")


def detect_prefix(directory: str) -> str:
    """Infers the ldeep output prefix from the `<prefix>__<name>.json` files present."""
    found = set()
    for name in DUMP_FILES:
        suffix = f"__{name}.json"
        for path in Path(directory).glob(f"*{suffix}"):
            prefix = path.name[: -len(suffix)]
            if prefix:
                found.add(prefix)

    if not found:
        raise ValueError(
            f"No ldeep dump files found in {directory} "
            f"(expected <prefix>__<name>.json, e.g. <prefix>__users_all.json)"
        )
    if len(found) > 1:
        raise ValueError(
            f"{directory} holds dumps for several prefixes ({', '.join(sorted(found))}); "
            "keep one dump per directory"
        )
    return found.pop()


def _load_json(path: Path) -> list:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


class LdeepDump:
    """Indexes every object from an ldeep dump directory by DN, SID and GUID,
    and separates records into BloodHound node types."""

    def __init__(self, directory: str, prefix: Optional[str] = None):
        self.directory = Path(directory)
        if prefix is None:
            prefix = detect_prefix(directory)
            log.info("Detected ldeep dump prefix %r", prefix)
        self.prefix = prefix

        self.users: list[dict] = []
        self.computers: list[dict] = []
        self.groups: list[dict] = []
        self.ous: list[dict] = []
        self.gpos: list[dict] = []
        self.domain: Optional[dict] = None
        self.trusts: list[dict] = []
        self.fsps: list[dict] = []

        self.by_dn: dict[str, tuple[dict, str]] = {}
        self.by_sid: dict[str, tuple[dict, str]] = {}
        self.by_guid: dict[str, tuple[dict, str]] = {}

        self._load()

    def _path(self, name: str) -> Path:
        return self.directory / f"{self.prefix}__{name}.json"

    def _index(self, record: dict, label: str) -> None:
        dn = record.get("distinguishedName") or record.get("dn")
        if dn:
            self.by_dn[dn_upper(dn)] = (record, label)
        sid = record.get("objectSid")
        if sid:
            self.by_sid[norm_sid(sid)] = (record, label)
        guid = record.get("objectGUID")
        if guid:
            self.by_guid[norm_guid(guid)] = (record, label)

    def _load(self) -> None:
        for rec in _load_json(self._path("users_all")):
            self.users.append(rec)
            self._index(rec, C.LABEL_USER)

        for rec in _load_json(self._path("machines")):
            self.computers.append(rec)
            self._index(rec, C.LABEL_COMPUTER)

        for rec in _load_json(self._path("groups")):
            self.groups.append(rec)
            self._index(rec, C.LABEL_GROUP)

        for rec in _load_json(self._path("gpo")):
            self.gpos.append(rec)
            self._index(rec, C.LABEL_GPO)

        for rec in _load_json(self._path("fsp")):
            self.fsps.append(rec)
            # Indexed by DN/SID so DN-based lookups (e.g. resolving a group's
            # "member" attribute that points at an FSP) succeed, but never
            # exposed as its own node type/bucket: FSP stubs get routed
            # through the well-known-SID table (for universal/BUILTIN SIDs)
            # or left as an unresolved SID, never emitted as a literal graph
            # node in their own right.
            self._index(rec, C.LABEL_BASE)

        domain_policy = _load_json(self._path("domain_policy"))
        if domain_policy:
            self.domain = domain_policy[0]
            self._index(self.domain, C.LABEL_DOMAIN)

        for rec in _load_json(self._path("ou")):
            object_classes = rec.get("objectClass") or []
            if "domain" in object_classes:
                if self.domain is None:
                    self.domain = rec
                    self._index(rec, C.LABEL_DOMAIN)
                continue
            self.ous.append(rec)
            self._index(rec, C.LABEL_OU)

        self.trusts = _load_json(self._path("trusts"))

    def resolve_dn(self, dn: str) -> Optional[tuple[dict, str]]:
        return self.by_dn.get(dn_upper(dn))

    def resolve_sid(self, sid: str) -> Optional[tuple[dict, str]]:
        return self.by_sid.get(norm_sid(sid))

    def domain_sid(self) -> Optional[str]:
        if self.domain is not None:
            sid = self.domain.get("objectSid")
            if sid:
                return norm_sid(sid)
        # Fall back to stripping the RID off any known domain-relative SID.
        for sid in self.by_sid:
            if sid.startswith("S-1-5-21-"):
                return "-".join(sid.split("-")[:-1])
        return None

    def domain_fqdn(self) -> Optional[str]:
        if self.domain is not None:
            dn = self.domain.get("distinguishedName") or self.domain.get("dn")
            if dn:
                return _dn_to_domain(dn)
        for rec in self.users + self.computers:
            dn = rec.get("distinguishedName") or rec.get("dn")
            if dn:
                return _dn_to_domain(dn)
        return None


def _dn_to_domain(dn: str) -> str:
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts).upper()
