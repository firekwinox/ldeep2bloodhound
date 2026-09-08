"""Orchestrates loader + acl + properties + wellknown into the 7 BloodHound
node-type lists ready for ingest_zip.py."""

from __future__ import annotations

import logging
from typing import Optional

from . import acl as acl_mod
from . import constants as C
from . import properties as P
from .loader import LdeepDump
from .sidutils import norm_guid, norm_sid, rdn_value
from .wellknown import WellKnownRegistry

log = logging.getLogger(__name__)


class GraphBuilder:
    def __init__(self, dump: LdeepDump):
        self.dump = dump
        self.domain_sid = dump.domain_sid()
        self.domain_fqdn = dump.domain_fqdn()
        if not self.domain_sid or not self.domain_fqdn:
            raise ValueError("Could not determine domain SID/FQDN from the ldeep dump")
        self.wkp = WellKnownRegistry(self.domain_fqdn, self.domain_sid)
        self._acl_warned = False
        self._wkp_emitted_ids: set[str] = set()

        self.nodes: dict[str, list[dict]] = {
            "users": [],
            "computers": [],
            "groups": [],
            "domains": [],
            "ous": [],
            "gpos": [],
            "containers": [],
        }
        # object_identifier -> node dict, used to invert ContainedBy into ChildObjects.
        self._by_id: dict[str, dict] = {}

    # -- principal resolution -------------------------------------------------

    def resolve_principal(self, sid: str) -> tuple[str, str]:
        sid = norm_sid(sid)
        wk = self.wkp.lookup(sid)
        if wk:
            return wk
        found = self.dump.resolve_sid(sid)
        if found:
            record, label = found
            return sid, label
        return sid, C.LABEL_BASE

    def _own_object_id(self, sid: str) -> str:
        """ObjectIdentifier to use for a node we're building from a real LDAP
        record. BUILTIN groups (S-1-5-32-*) exist as real objects in the
        BUILTIN container, but BloodHound always identifies them by the
        well-known domain-scoped ID rather than their raw SID. Record the mapping so _merge_well_known() doesn't also
        emit a redundant minimal duplicate for the same ID."""
        sid = norm_sid(sid)
        wk = self.wkp.lookup(sid)
        if wk:
            object_id, _label = wk
            self._wkp_emitted_ids.add(object_id)
            return object_id
        return sid

    def _display_name(self, sid: str, fallback_sam: str) -> str:
        """Well-known/BUILTIN objects use their canonical well-known display
        name (e.g. "Replicators") even when a real LDAP object exists with a
        different actual sAMAccountName (e.g. "Replicator", singular - a real
        default-schema quirk, confirmed by diffing against a real SharpHound
        collection of this domain)."""
        entry = C.WELL_KNOWN_PRINCIPALS.get(norm_sid(sid))
        name = entry[0] if entry else fallback_sam
        return self._upn_name(name)

    def _process_sd(self, record: dict, label: str, has_laps: bool = False):
        # ldeep is inconsistent about this attribute's key casing depending on
        # which internal code path fetched it ("nTSecurityDescriptor" for
        # some commands, "ntSecurityDescriptor" for others via --security_desc's
        # own literal) - accept either.
        sd = record.get("nTSecurityDescriptor") or record.get("ntSecurityDescriptor")
        if isinstance(sd, list):
            # Empty list = attribute requested but unreadable for this object
            # (e.g. our collection account lacks rights on a high-priv
            # principal like a Domain Admin); non-empty is defensive.
            sd = sd[0] if sd else None
        if not sd:
            if not self._acl_warned:
                log.warning(
                    "Dump has no nTSecurityDescriptor data (re-run ldeep collection with "
                    "--security_desc to include ACLs) - producing a zip with empty Aces."
                )
                self._acl_warned = True
            return [], False, (False, False)
        aces = acl_mod.process_sd(sd, label, self.resolve_principal, has_laps=has_laps)
        return aces, acl_mod.is_acl_protected(sd), acl_mod.owner_rights_flags(sd)

    @staticmethod
    def _apply_acl_props(props: dict, protected: bool, owner_rights: tuple[bool, bool]) -> None:
        props["isaclprotected"] = protected
        props["doesanyacegrantownerrights"] = owner_rights[0]
        props["doesanyinheritedacegrantownerrights"] = owner_rights[1]

    # -- name computation -------------------------------------------------------

    def _upn_name(self, sam: str) -> str:
        return f"{sam}@{self.domain_fqdn}".upper()

    # -- build --------------------------------------------------------------

    def build(self) -> dict[str, list[dict]]:
        self._build_domain()
        self._build_ous()
        self._build_gpos()
        self._build_groups()
        self._build_users()
        self._build_computers()
        self._link_children()
        self._merge_well_known()
        return self.nodes

    def _register(self, node: dict, bucket: str) -> None:
        self.nodes[bucket].append(node)
        self._by_id[node["ObjectIdentifier"]] = node

    def _build_domain(self) -> None:
        record = self.dump.domain
        if record is None:
            return
        aces, protected, owner_rights = self._process_sd(record, C.LABEL_DOMAIN)
        data = P.read_domain_properties(record)
        props = data["Properties"]
        self._apply_acl_props(props, protected, owner_rights)
        props["name"] = self.domain_fqdn
        props["domain"] = self.domain_fqdn
        props["distinguishedname"] = (record.get("distinguishedName") or record.get("dn") or "").upper()
        props["domainsid"] = self.domain_sid

        node = {
            "ObjectIdentifier": self.domain_sid,
            "IsDeleted": False,
            "IsACLProtected": protected,
            "Properties": props,
            "Aces": aces,
            "Trusts": self._build_trusts(),
            "Links": P.gplinks(record.get("gPLink"), self.dump),
            "ChildObjects": [],
            "GPOChanges": {
                "LocalAdmins": [],
                "RemoteDesktopUsers": [],
                "DcomUsers": [],
                "PSRemoteUsers": [],
                "AffectedComputers": [],
            },
        }
        self._register(node, "domains")

    def _build_trusts(self) -> list[dict]:
        out = []
        for t in self.dump.trusts:
            sid = t.get("securityIdentifier") or t.get("objectSid")
            attrs = t.get("trustAttributes")
            direction = t.get("trustDirection")
            try:
                attrs = int(attrs)
            except (TypeError, ValueError):
                attrs = 0
            try:
                direction = int(direction)
            except (TypeError, ValueError):
                direction = 0
            within_forest = bool(attrs & C.TRUST_ATTR_WITHIN_FOREST)
            forest_transitive = bool(attrs & C.TRUST_ATTR_FOREST_TRANSITIVE)
            quarantined = bool(attrs & C.TRUST_ATTR_QUARANTINED_DOMAIN)
            treat_as_external = bool(attrs & C.TRUST_ATTR_TREAT_AS_EXTERNAL)
            cross_org_tgt = bool(attrs & C.TRUST_ATTR_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION)

            if within_forest:
                trust_type = "ParentChild"
            elif forest_transitive:
                trust_type = "Forest"
            else:
                trust_type = "External"

            out.append(
                {
                    "TargetDomainSid": sid,
                    "TargetDomainName": (t.get("cn") or t.get("name") or "").upper(),
                    "IsTransitive": not bool(attrs & C.TRUST_ATTR_NON_TRANSITIVE),
                    "SidFilteringEnabled": quarantined or (forest_transitive and not treat_as_external),
                    "TGTDelegationEnabled": (not quarantined) and (within_forest or cross_org_tgt),
                    "TrustDirection": C.TRUST_DIRECTION_MAP.get(direction, "Disabled"),
                    "TrustType": trust_type,
                }
            )
        return out

    def _build_ous(self) -> None:
        for record in self.dump.ous:
            aces, protected, owner_rights = self._process_sd(record, C.LABEL_OU)
            data = P.read_ou_properties(record)
            props = data["Properties"]
            self._apply_acl_props(props, protected, owner_rights)
            props["domain"] = self.domain_fqdn
            props["domainsid"] = self.domain_sid
            props["distinguishedname"] = (record.get("distinguishedName") or record.get("dn") or "").upper()
            props["name"] = self._upn_name(rdn_value(record.get("distinguishedName", record.get("dn", ""))))

            node = {
                "ObjectIdentifier": norm_guid(record["objectGUID"]),
                "IsDeleted": False,
                "IsACLProtected": protected,
                "Properties": props,
                "Aces": aces,
                "Links": P.gplinks(record.get("gPLink"), self.dump),
                "ChildObjects": [],
                "GPOChanges": {
                    "LocalAdmins": [],
                    "RemoteDesktopUsers": [],
                    "DcomUsers": [],
                    "PSRemoteUsers": [],
                    "AffectedComputers": [],
                },
                "ContainedBy": P.contained_by(record, self.dump, self.domain_sid),
                "_dn": record.get("distinguishedName") or record.get("dn"),
            }
            self._register(node, "ous")

    def _build_gpos(self) -> None:
        for record in self.dump.gpos:
            aces, protected, owner_rights = self._process_sd(record, C.LABEL_GPO)
            data = P.read_gpo_properties(record)
            props = data["Properties"]
            self._apply_acl_props(props, protected, owner_rights)
            props["domain"] = self.domain_fqdn
            props["domainsid"] = self.domain_sid
            props["distinguishedname"] = (record.get("distinguishedName") or record.get("dn") or "").upper()
            props["name"] = self._upn_name(record.get("displayName", record.get("cn", "")))

            node = {
                "ObjectIdentifier": norm_guid(record["objectGUID"]),
                "IsDeleted": False,
                "IsACLProtected": protected,
                "Properties": props,
                "Aces": aces,
                "ContainedBy": P.contained_by(record, self.dump, self.domain_sid),
                "_dn": record.get("distinguishedName") or record.get("dn"),
            }
            self._register(node, "gpos")

    def _build_groups(self) -> None:
        for record in self.dump.groups:
            aces, protected, owner_rights = self._process_sd(record, C.LABEL_GROUP)
            data = P.read_group_properties(record, self.dump, self.resolve_principal)
            props = data["Properties"]
            self._apply_acl_props(props, protected, owner_rights)
            props["domain"] = self.domain_fqdn
            props["domainsid"] = self.domain_sid
            props["distinguishedname"] = (record.get("distinguishedName") or record.get("dn") or "").upper()
            props["name"] = self._display_name(record["objectSid"], record.get("sAMAccountName", ""))

            node = {
                "ObjectIdentifier": self._own_object_id(record["objectSid"]),
                "IsDeleted": False,
                "IsACLProtected": protected,
                "Properties": props,
                "Aces": aces,
                "Members": data["Members"],
                "HasSIDHistory": data["HasSIDHistory"],
                "ContainedBy": P.contained_by(record, self.dump, self.domain_sid),
                "_dn": record.get("distinguishedName") or record.get("dn"),
            }
            self._register(node, "groups")

    def _build_users(self) -> None:
        for record in self.dump.users:
            aces, protected, owner_rights = self._process_sd(record, C.LABEL_USER)
            data = P.read_user_properties(record, self.dump, self.domain_fqdn, self.resolve_principal)
            props = data["Properties"]
            self._apply_acl_props(props, protected, owner_rights)
            props["domain"] = self.domain_fqdn
            props["domainsid"] = self.domain_sid
            props["distinguishedname"] = (record.get("distinguishedName") or record.get("dn") or "").upper()
            props["name"] = self._display_name(record["objectSid"], record.get("sAMAccountName", ""))

            node = {
                "ObjectIdentifier": self._own_object_id(record["objectSid"]),
                "IsDeleted": False,
                "IsACLProtected": protected,
                "Properties": props,
                "Aces": aces,
                "AllowedToDelegate": data["AllowedToDelegate"],
                "PrimaryGroupSID": P.primary_group_sid(self.domain_sid, record.get("primaryGroupID")),
                "HasSIDHistory": data["HasSIDHistory"],
                "SpnTargets": data["SpnTargets"],
                "ContainedBy": P.contained_by(record, self.dump, self.domain_sid),
                "_dn": record.get("distinguishedName") or record.get("dn"),
            }
            self._register(node, "users")

    def _build_computers(self) -> None:
        for record in self.dump.computers:
            has_laps = P.has_laps(record)
            aces, protected, owner_rights = self._process_sd(record, C.LABEL_COMPUTER, has_laps=has_laps)
            data = P.read_computer_properties(record, self.dump, self.domain_fqdn, self.resolve_principal)
            props = data["Properties"]
            self._apply_acl_props(props, protected, owner_rights)
            props["domain"] = self.domain_fqdn
            props["domainsid"] = self.domain_sid
            props["distinguishedname"] = (record.get("distinguishedName") or record.get("dn") or "").upper()
            dns_host = record.get("dNSHostName")
            sam = (record.get("sAMAccountName") or "").rstrip("$")
            props["name"] = dns_host.upper() if dns_host else f"{sam}.{self.domain_fqdn}".upper()

            node = {
                "ObjectIdentifier": self._own_object_id(record["objectSid"]),
                "IsDeleted": False,
                "IsACLProtected": protected,
                "Properties": props,
                "Aces": aces,
                "AllowedToDelegate": data["AllowedToDelegate"],
                "AllowedToAct": data["AllowedToAct"],
                "PrimaryGroupSID": P.primary_group_sid(self.domain_sid, record.get("primaryGroupID")),
                "HasSIDHistory": data["HasSIDHistory"],
                "UnconstrainedDelegation": data["UnconstrainedDelegation"],
                "IsDC": data["IsDC"],
                "DomainSID": self.domain_sid,
                "Sessions": data["Sessions"],
                "PrivilegedSessions": data["PrivilegedSessions"],
                "RegistrySessions": data["RegistrySessions"],
                "LocalGroups": data["LocalGroups"],
                "UserRights": data["UserRights"],
                "Status": data["Status"],
                "ContainedBy": P.contained_by(record, self.dump, self.domain_sid),
                "_dn": record.get("distinguishedName") or record.get("dn"),
            }
            self._register(node, "computers")

    def _link_children(self) -> None:
        """Invert ContainedBy -> ChildObjects for OU/Domain nodes (Container
        nodes aren't emitted at all - see loader.py note on scope)."""
        containers_by_id = {n["ObjectIdentifier"]: n for n in self.nodes["ous"]}
        if self.nodes["domains"]:
            containers_by_id[self.domain_sid] = self.nodes["domains"][0]

        for bucket, label in (
            ("users", C.LABEL_USER),
            ("computers", C.LABEL_COMPUTER),
            ("groups", C.LABEL_GROUP),
            ("gpos", C.LABEL_GPO),
            ("ous", C.LABEL_OU),
        ):
            for node in self.nodes[bucket]:
                contained_by = node.get("ContainedBy")
                if not contained_by:
                    continue
                parent = containers_by_id.get(contained_by["ObjectIdentifier"])
                if parent is not None and parent is not node and "ChildObjects" in parent:
                    parent["ChildObjects"].append({"ObjectIdentifier": node["ObjectIdentifier"], "ObjectType": label})

        for bucket in ("users", "computers", "groups", "gpos", "ous"):
            for node in self.nodes[bucket]:
                node.pop("_dn", None)

    def _merge_well_known(self) -> None:
        for node in self.wkp.synthetic_nodes():
            if node["ObjectIdentifier"] in self._wkp_emitted_ids:
                # Already emitted as a full node built from a real LDAP
                # record (e.g. a BUILTIN group that exists as a genuine
                # object) - don't also add a minimal duplicate.
                continue
            label = node.pop("label")
            bucket = {
                C.LABEL_USER: "users",
                C.LABEL_GROUP: "groups",
                C.LABEL_COMPUTER: "computers",
            }.get(label)
            if bucket:
                self.nodes[bucket].append(node)


def build_graph(directory: str, prefix: Optional[str] = None) -> dict[str, list[dict]]:
    dump = LdeepDump(directory, prefix)
    return GraphBuilder(dump).build()
