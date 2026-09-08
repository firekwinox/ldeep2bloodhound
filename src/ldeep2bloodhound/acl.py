"""Turns ldeep's parsed ntSecurityDescriptor dict into BloodHound ACE edges.

Ported from SharpHoundCommon's ACLProcessor.cs (SpecterOps/SharpHoundCommon@v4)
"""

from __future__ import annotations

from typing import Callable, Optional

from ldeep.views.constants import ADRights

from . import constants as C

# SDDL "Type" control flag for "DACL Protected" (see ldeep.utils.sddl.SDDLTypeFlags).
# ldeep deletes the decoded "Type" dict before returning, but keeps "Raw Type",
# so we re-derive this one bit ourselves.
_DACL_PROTECTED_BIT = 0b0001000000000000

# ACE "Raw Flags" bit for INHERITED_ACE (verified against real ACE data:
# Raw Flags 18 = 0x12 = inherited + container-inherit, vs 0 = explicit).
_INHERITED_ACE_BIT = 0x10

_IGNORED_PRINCIPAL_SIDS = {"S-1-5-18", "S-1-3-0", "S-1-5-10"}

# Types that grant rights we process. Deny ACEs (and their Object variant)
# never produce edges (SharpHound never emits Deny edges).
_ALLOW_TYPES = {"Access Allowed", "Access Allowed Object"}

ResolvePrincipal = Callable[[str], "tuple[str, str]"]
"""sid -> (object_identifier, bloodhound_label). Must never raise; unknown
SIDs should resolve to (sid, "Base")."""


def is_acl_protected(sd: dict) -> bool:
    raw_type = sd.get("Raw Type", 0) or 0
    return bool(raw_type & _DACL_PROTECTED_BIT)


_OWNER_RIGHTS_SID = "S-1-3-4"


def owner_rights_flags(sd: Optional[dict]) -> tuple[bool, bool]:
    """(doesanyacegrantownerrights, doesanyinheritedacegrantownerrights):
    whether any (explicit / inherited) allow ACE's principal is the special
    "Owner Rights" SID, which overrides the implicit owner-always-has-rights
    behavior. Node-level properties confirmed against a real collection."""
    if not sd:
        return False, False
    explicit = inherited = False
    for ace in (sd.get("DACL") or {}).get("ACEs", []):
        if ace.get("Type", "") not in _ALLOW_TYPES:
            continue
        if (ace.get("SID") or "").upper() != _OWNER_RIGHTS_SID:
            continue
        if (ace.get("Raw Flags", 0) or 0) & _INHERITED_ACE_BIT:
            inherited = True
        else:
            explicit = True
    return explicit, inherited


def _ace_type_guid(ace: dict) -> str:
    """Lowercased Object Type GUID for this ACE, or "" if it's not an Object ACE."""
    guid = ace.get("GUID")
    if not guid:
        return ""
    return guid.strip("{}").lower()


def _applies_to(ace: dict, label: str) -> bool:
    """Mirrors ACLProcessor.cs's IsAceInheritedFrom(BaseGuids[objectType]) filter:
    an ACE only applies to this object if it has no "Inherited Object Type" GUID,
    or that GUID matches the object's own schema class GUID."""
    inherited_guid = ace.get("Inherited GUID")
    if not inherited_guid:
        return True
    base_guid = C.BASE_CLASS_GUIDS.get(label)
    if base_guid is None:
        return True
    return inherited_guid.strip("{}").lower() == base_guid.lower()


def process_sd(
    sd: Optional[dict],
    label: str,
    resolve_principal: ResolvePrincipal,
    has_laps: bool = False,
) -> list[dict]:
    """sd: ldeep's parsed ntSecurityDescriptor dict (or None if not collected).
    label: this object's BloodHound Label (User/Computer/Group/Domain/OU/GPO/Container).
    resolve_principal: sid -> (object_id, label) resolver (never raises).
    has_laps: only meaningful for Computer objects (gates ReadLAPSPassword/AllExtendedRights).

    Returns a list of {"PrincipalSID", "PrincipalType", "RightName", "IsInherited"}.
    """
    if not sd:
        return []

    aces: list[dict] = []

    owner_sid = sd.get("Owner SID")
    if owner_sid and owner_sid.upper() not in _IGNORED_PRINCIPAL_SIDS:
        obj_id, obj_type = resolve_principal(owner_sid)
        aces.append(
            {
                "PrincipalSID": obj_id,
                "PrincipalType": obj_type,
                "RightName": C.RIGHT_OWNS,
                "IsInherited": False,
            }
        )

    dacl_aces = (sd.get("DACL") or {}).get("ACEs", [])

    for ace in dacl_aces:
        ace_kind = ace.get("Type", "")
        if ace_kind not in _ALLOW_TYPES:
            continue

        if not _applies_to(ace, label):
            continue

        principal_sid = (ace.get("SID") or "").upper()
        if not principal_sid or principal_sid in _IGNORED_PRINCIPAL_SIDS:
            continue

        obj_id, obj_type = resolve_principal(principal_sid)
        rights = ace.get("Raw Access Required", 0) or 0
        ace_type = _ace_type_guid(ace)
        inherited = bool((ace.get("Raw Flags", 0) or 0) & _INHERITED_ACE_BIT)

        def emit(right_name: str) -> dict:
            return {
                "PrincipalSID": obj_id,
                "PrincipalType": obj_type,
                "RightName": right_name,
                "IsInherited": inherited,
            }

        def has(flag_name: str) -> bool:
            # Mirrors .NET's [Flags] HasFlag: rights must contain *every* bit
            # of the (possibly composite) target mask, not just overlap it.
            # GenericAll/GenericWrite in ADRights are composite masks
            # (0xF01FF / 0x20028) — plain "rights & flag != 0" over-matches
            # them against e.g. a lone GenericRead ACE, which shares bits
            # with GenericAll but isn't it.
            flag = ADRights[flag_name]
            return (rights & flag) == flag

        # GenericAll / WriteDacl / WriteOwner only apply when the ACE isn't
        # scoped to a specific attribute/right GUID.
        if ace_type in ("", C.GUID_ALL_EXTENDED_RIGHTS):
            if has("GenericAll"):
                aces.append(emit(C.RIGHT_GENERIC_ALL))
                # GenericAll subsumes every other right on this ACE.
                continue
            if has("WriteDacl"):
                aces.append(emit(C.RIGHT_WRITE_DACL))
            if has("WriteOwner"):
                aces.append(emit(C.RIGHT_WRITE_OWNER))

        # AddSelf: "Self" right, not combined with WriteProperty/GenericWrite,
        # only on Group objects, and only for the member/self-membership GUIDs.
        if (
            has("Self")
            and not has("WriteProperty")
            and not has("GenericWrite")
            and label == C.LABEL_GROUP
            and ace_type in (C.GUID_SELF_MEMBERSHIP, C.GUID_MEMBERSHIP_PROPERTY_SET, "", C.GUID_ALL_EXTENDED_RIGHTS)
        ):
            aces.append(emit(C.RIGHT_ADD_SELF))

        # Extended rights (and GenericAll, which also grants them).
        if has("ExtendedRight") or has("GenericAll"):
            if label == C.LABEL_DOMAIN:
                if ace_type == C.GUID_DS_REPL_GET_CHANGES:
                    aces.append(emit(C.RIGHT_GET_CHANGES))
                elif ace_type == C.GUID_DS_REPL_GET_CHANGES_ALL:
                    aces.append(emit(C.RIGHT_GET_CHANGES_ALL))
                elif ace_type == C.GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET:
                    aces.append(emit(C.RIGHT_GET_CHANGES_IN_FILTERED_SET))
                elif ace_type in ("", C.GUID_ALL_EXTENDED_RIGHTS):
                    aces.append(emit(C.RIGHT_ALL_EXTENDED_RIGHTS))
            elif label == C.LABEL_USER:
                if ace_type == C.GUID_USER_FORCE_CHANGE_PASSWORD:
                    aces.append(emit(C.RIGHT_FORCE_CHANGE_PASSWORD))
                elif ace_type in ("", C.GUID_ALL_EXTENDED_RIGHTS):
                    aces.append(emit(C.RIGHT_ALL_EXTENDED_RIGHTS))
            elif label == C.LABEL_COMPUTER and has_laps:
                if ace_type in ("", C.GUID_ALL_EXTENDED_RIGHTS):
                    aces.append(emit(C.RIGHT_ALL_EXTENDED_RIGHTS))
                # (Specific LAPS-attribute GUID -> ReadLAPSPassword requires a
                # schema GUID cache lookup we don't have offline; the coarse
                # AllExtendedRights-when-hasLaps case above is what fires for
                # the common "grant all extended rights" ACE shape.)

        # GenericWrite / WriteProperty (and GenericAll, which also grants them).
        if has("GenericWrite") or has("WriteProperty") or has("GenericAll"):
            if label in (
                C.LABEL_USER,
                C.LABEL_GROUP,
                C.LABEL_COMPUTER,
                C.LABEL_GPO,
                C.LABEL_OU,
                C.LABEL_DOMAIN,
            ):
                if ace_type in ("", C.GUID_ALL_EXTENDED_RIGHTS):
                    aces.append(emit(C.RIGHT_GENERIC_WRITE))

            if label == C.LABEL_USER and ace_type == C.GUID_ATTR_SERVICE_PRINCIPAL_NAME:
                aces.append(emit(C.RIGHT_WRITE_SPN))
            elif label == C.LABEL_COMPUTER and ace_type == C.GUID_ATTR_MS_DS_ALLOWED_TO_ACT_ON_BEHALF:
                aces.append(emit(C.RIGHT_ALLOWED_TO_ACT))
            elif label == C.LABEL_COMPUTER and ace_type == C.GUID_ACCOUNT_RESTRICTIONS:
                aces.append(emit(C.RIGHT_WRITE_ACCOUNT_RESTRICTIONS))
            elif label in (C.LABEL_OU, C.LABEL_DOMAIN) and ace_type == C.GUID_WRITE_GPLINK:
                aces.append(emit(C.RIGHT_WRITE_GPLINK))
            elif label == C.LABEL_GROUP and ace_type in (C.GUID_ATTR_MEMBER, C.GUID_MEMBERSHIP_PROPERTY_SET):
                aces.append(emit(C.RIGHT_ADD_MEMBER))
            elif label in (C.LABEL_USER, C.LABEL_COMPUTER) and ace_type == C.GUID_ATTR_MS_DS_KEY_CREDENTIAL_LINK:
                aces.append(emit(C.RIGHT_ADD_KEY_CREDENTIAL_LINK))
            elif label in (C.LABEL_USER, C.LABEL_COMPUTER) and ace_type == C.GUID_WRITE_ALT_SECURITY_IDENTITIES:
                aces.append(emit(C.RIGHT_WRITE_ALT_SECURITY_IDENTITIES))
            elif label in (C.LABEL_USER, C.LABEL_COMPUTER) and ace_type == C.GUID_WRITE_PUBLIC_INFORMATION:
                aces.append(emit(C.RIGHT_WRITE_PUBLIC_INFORMATION))

    return aces
