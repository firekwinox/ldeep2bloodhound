"""Well-known SID -> synthetic BloodHound node, per SharpHoundCommonLib's
WellKnownPrincipal.cs / LdapUtils.cs (verified against source).
"""

from __future__ import annotations

from . import constants as C


def object_id_for(sid: str, domain_fqdn: str, forest_fqdn: str) -> str:
    """Domain- (or, for S-1-5-9, forest-) scoped ID SharpHound uses for a
    well-known SID, so the same universal SID from different domains doesn't
    collide in the graph."""
    scope = forest_fqdn if sid.upper() in C.FOREST_SCOPED_WELL_KNOWN_SIDS else domain_fqdn
    return f"{scope}-{sid}".upper()


class WellKnownRegistry:
    """Tracks which well-known SIDs were actually referenced during a
    conversion run, so we only emit synthetic nodes for those (matching
    SharpHound's SeenWellKnownPrincipals behavior) rather than all of them."""

    def __init__(self, domain_fqdn: str, domain_sid: str, forest_fqdn: str | None = None):
        self.domain_fqdn = domain_fqdn.upper()
        self.domain_sid = domain_sid
        self.forest_fqdn = (forest_fqdn or domain_fqdn).upper()
        self._seen: dict[str, tuple[str, str, str]] = {}  # sid -> (object_id, label, name)

    def lookup(self, sid: str) -> tuple[str, str] | None:
        """Returns (object_id, label) if `sid` is a well-known SID, recording
        it as seen; otherwise returns None (caller should resolve normally)."""
        sid = sid.upper()
        entry = C.WELL_KNOWN_PRINCIPALS.get(sid)
        if entry is None:
            return None
        name, label = entry
        object_id = object_id_for(sid, self.domain_fqdn, self.forest_fqdn)
        self._seen[sid] = (object_id, label, name)
        return object_id, label

    def synthetic_nodes(self) -> list[dict]:
        """One minimal OutputBase-shaped record per referenced well-known SID,
        matching SharpHound's GetWellKnownPrincipalOutput property shape."""
        nodes = []
        for object_id, label, name in self._seen.values():
            nodes.append(
                {
                    "label": label,
                    "ObjectIdentifier": object_id,
                    "IsDeleted": False,
                    "IsACLProtected": False,
                    "Properties": {
                        "name": f"{name}@{self.domain_fqdn}".upper(),
                        "domain": self.domain_fqdn,
                        "domainsid": self.domain_sid,
                    },
                    "Aces": [],
                }
            )
        return nodes
