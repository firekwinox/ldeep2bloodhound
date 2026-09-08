"""Per-object-type BloodHound `Properties` dict + top-level fields (PrimaryGroupSID,
AllowedToDelegate, AllowedToAct, HasSIDHistory, ContainedBy, ...).

Ported from SharpHoundCommon's LdapPropertyProcessor.cs / GroupProcessor.cs /
ContainerProcessor.cs / SPNProcessors.cs, adapted because ldeep pre-decodes
flag attributes (userAccountControl, groupType, msDS-SupportedEncryptionTypes,
sAMAccountType) to "FLAG_A | FLAG_B" strings instead of raw ints.
"""

from __future__ import annotations

import base64
from typing import Optional

from ldeep.utils.sddl import parse_ntSecurityDescriptor

from . import acl as acl_mod
from . import constants as C
from .loader import LdeepDump
from .sidutils import as_list, iso_to_epoch, parent_dn, rdn_value, uac_has

ResolvePrincipal = acl_mod.ResolvePrincipal


def _common_props(record: dict) -> dict:
    props: dict = {}
    if record.get("description") is not None:
        props["description"] = record.get("description")
    props["whencreated"] = iso_to_epoch(record.get("whenCreated"), zero_is_never=False)
    guid = record.get("objectGUID")
    if guid:
        from .sidutils import norm_guid

        props["objectguid"] = norm_guid(guid)
    return props


# ldeep's msDS-SupportedEncryptionTypes decoding names don't all match
# BloodHound's expected strings (confirmed against a real collection).
_ENC_TYPE_RENAME = {"RC4-HMAC": "RC4-HMAC-MD5"}


def _encryption_types(record: dict) -> list[str]:
    raw = record.get("msDS-SupportedEncryptionTypes")
    if not raw or raw == "NONE":
        return []
    return [_ENC_TYPE_RENAME.get(t.strip(), t.strip()) for t in raw.split("|")]


def _reconstruct_uac_int(uac_str: str) -> int:
    """ldeep decodes userAccountControl to a "FLAG_A | FLAG_B" string rather
    than keeping the raw int; reconstruct it by OR-ing the bit values of every
    flag name ldeep's own table recognizes in that string."""
    from ldeep.views.constants import USER_ACCOUNT_CONTROL

    tokens = {t.strip() for t in (uac_str or "").split("|")}
    value = 0
    for bit, name in USER_ACCOUNT_CONTROL.items():
        if name in tokens:
            value |= bit
    return value


def has_laps(record: dict) -> bool:
    return bool(record.get("ms-Mcs-AdmPwdExpirationTime") or record.get("msLAPS-PasswordExpirationTime"))


def _hostname_index(dump: LdeepDump) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for comp in dump.computers:
        dns = comp.get("dNSHostName")
        if dns:
            index[dns.upper()] = comp
        sam = comp.get("sAMAccountName")
        if sam:
            index[sam.upper().rstrip("$")] = comp
            index[sam.upper()] = comp
    return index


def _strip_spn_host(spn: str) -> str:
    # "cifs/dc01.domain.com:1234" -> "dc01.domain.com"
    if "/" in spn:
        spn = spn.split("/", 1)[1]
    if ":" in spn:
        spn = spn.split(":", 1)[0]
    return spn


def resolve_allowed_to_delegate(record: dict, dump: LdeepDump, resolve_principal: ResolvePrincipal) -> list[dict]:
    spns = as_list(record.get("msDS-AllowedToDelegateTo"))
    if not spns:
        return []
    hostnames = _hostname_index(dump)
    seen: set[str] = set()
    out = []
    for spn in spns:
        host = _strip_spn_host(spn).upper()
        target = hostnames.get(host)
        if target is None:
            continue
        sid = target.get("objectSid")
        if not sid or sid in seen:
            continue
        seen.add(sid)
        obj_id, obj_type = resolve_principal(sid)
        out.append({"ObjectIdentifier": obj_id, "ObjectType": obj_type})
    return out


def resolve_allowed_to_act(record: dict, resolve_principal: ResolvePrincipal) -> list[dict]:
    raw = record.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
    if not raw:
        return []
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw:
        return []
    try:
        blob = base64.b64decode(raw)
        sd = parse_ntSecurityDescriptor(blob)
    except Exception:
        return []
    out = []
    for ace in (sd.get("DACL") or {}).get("ACEs", []):
        sid = ace.get("SID")
        if not sid:
            continue
        obj_id, obj_type = resolve_principal(sid)
        out.append({"ObjectIdentifier": obj_id, "ObjectType": obj_type})
    return out


def sid_history(record: dict, resolve_principal: ResolvePrincipal) -> tuple[list[str], list[dict]]:
    sids = as_list(record.get("sIDHistory"))
    principals = []
    for sid in sids:
        obj_id, obj_type = resolve_principal(sid)
        principals.append({"ObjectIdentifier": obj_id, "ObjectType": obj_type})
    return sids, principals


def primary_group_sid(domain_sid: Optional[str], primary_group_id) -> Optional[str]:
    if not domain_sid or primary_group_id is None:
        return None
    return f"{domain_sid}-{primary_group_id}"


def contained_by(record: dict, dump: LdeepDump, domain_sid: str) -> Optional[dict]:
    dn = record.get("distinguishedName") or record.get("dn")
    if not dn:
        return None
    current = parent_dn(dn)
    while current:
        if current.upper().startswith("CN=BUILTIN,"):
            return {"ObjectIdentifier": domain_sid, "ObjectType": C.LABEL_DOMAIN}
        found = dump.resolve_dn(current)
        if found:
            parent_record, label = found
            if label == C.LABEL_DOMAIN:
                return {"ObjectIdentifier": parent_record.get("objectSid", domain_sid), "ObjectType": C.LABEL_DOMAIN}
            if label == C.LABEL_OU:
                return {"ObjectIdentifier": _guid_id(parent_record), "ObjectType": C.LABEL_OU}
        current = parent_dn(current)
    return None


def _guid_id(record: dict) -> str:
    from .sidutils import norm_guid

    return norm_guid(record.get("objectGUID", ""))


def read_user_properties(record: dict, dump: LdeepDump, domain: str, resolve_principal: ResolvePrincipal) -> dict:
    props = _common_props(record)
    uac = record.get("userAccountControl", "") or ""
    props["sensitive"] = uac_has(uac, "NOT_DELEGATED")
    props["dontreqpreauth"] = uac_has(uac, "DONT_REQ_PREAUTH")
    props["passwordnotreqd"] = uac_has(uac, "PASSWD_NOTREQD")
    props["unconstraineddelegation"] = uac_has(uac, "TRUSTED_FOR_DELEGATION")
    props["pwdneverexpires"] = uac_has(uac, "DONT_EXPIRE_PASSWORD")
    props["enabled"] = not uac_has(uac, "ACCOUNTDISABLE")
    props["trustedtoauth"] = uac_has(uac, "TRUSTED_TO_AUTH_FOR_DELEGATION")
    props["smartcardrequired"] = uac_has(uac, "SMARTCARD_REQUIRED")
    props["lockedout"] = uac_has(uac, "LOCKOUT")
    props["passwordcantchange"] = uac_has(uac, "PASSWD_CANT_CHANGE")
    props["passwordexpired"] = uac_has(uac, "PASSWORD_EXPIRED")
    props["encryptedtextpwdallowed"] = uac_has(uac, "ENCRYPTED_TEXT_PWD_ALLOWED")
    props["usedeskeyonly"] = uac_has(uac, "USE_DES_KEY_ONLY")
    props["logonscriptenabled"] = uac_has(uac, "SCRIPT")
    props["useraccountcontrol"] = _reconstruct_uac_int(uac)

    props["lastlogon"] = iso_to_epoch(record.get("lastLogon"))
    props["lastlogontimestamp"] = iso_to_epoch(record.get("lastLogonTimestamp"))
    props["pwdlastset"] = iso_to_epoch(record.get("pwdLastSet"))

    spns = as_list(record.get("servicePrincipalName"))
    props["serviceprincipalnames"] = spns
    props["hasspn"] = len(spns) > 0
    props["admincount"] = bool(record.get("adminCount"))
    props["displayname"] = record.get("displayName")
    props["email"] = record.get("mail")
    props["title"] = record.get("title")
    props["homedirectory"] = record.get("homeDirectory")
    props["samaccountname"] = record.get("sAMAccountName")
    props["supportedencryptiontypes"] = _encryption_types(record)

    sids, principals = sid_history(record, resolve_principal)
    props["sidhistory"] = sids

    return {
        "Properties": props,
        "PrimaryGroupSID": None,  # filled by build.py once domain SID is known
        "AllowedToDelegate": resolve_allowed_to_delegate(record, dump, resolve_principal),
        "HasSIDHistory": principals,
        "SpnTargets": [],
    }


def read_computer_properties(record: dict, dump: LdeepDump, domain: str, resolve_principal: ResolvePrincipal) -> dict:
    props = _common_props(record)
    uac = record.get("userAccountControl", "") or ""
    props["enabled"] = not uac_has(uac, "ACCOUNTDISABLE")
    props["unconstraineddelegation"] = uac_has(uac, "TRUSTED_FOR_DELEGATION")
    props["trustedtoauth"] = uac_has(uac, "TRUSTED_TO_AUTH_FOR_DELEGATION")
    props["isdc"] = uac_has(uac, "SERVER_TRUST_ACCOUNT")
    props["isreadonlydc"] = uac_has(uac, "PARTIAL_SECRETS_ACCOUNT")
    props["lockedout"] = uac_has(uac, "LOCKOUT")
    props["passwordexpired"] = uac_has(uac, "PASSWORD_EXPIRED")
    props["encryptedtextpwdallowed"] = uac_has(uac, "ENCRYPTED_TEXT_PWD_ALLOWED")
    props["usedeskeyonly"] = uac_has(uac, "USE_DES_KEY_ONLY")
    props["logonscriptenabled"] = uac_has(uac, "SCRIPT")
    props["useraccountcontrol"] = _reconstruct_uac_int(uac)
    props["haslaps"] = has_laps(record)

    props["lastlogon"] = iso_to_epoch(record.get("lastLogon"))
    props["lastlogontimestamp"] = iso_to_epoch(record.get("lastLogonTimestamp"))
    props["pwdlastset"] = iso_to_epoch(record.get("pwdLastSet"))

    spns = as_list(record.get("servicePrincipalName"))
    props["serviceprincipalnames"] = spns
    props["admincount"] = bool(record.get("adminCount"))
    props["email"] = record.get("mail")
    props["samaccountname"] = record.get("sAMAccountName")
    props["supportedencryptiontypes"] = _encryption_types(record)

    # SharpHound appends the *service pack*, not the OS version, to
    # operatingsystem (confirmed against a real collection - DC01 shows
    # "Windows Server 2025 Standard" with no version suffix even though
    # operatingSystemVersion is populated).
    os_name = record.get("operatingSystem")
    service_pack = record.get("operatingSystemServicePack")
    props["operatingsystem"] = f"{os_name} {service_pack}" if os_name and service_pack else os_name

    sids, principals = sid_history(record, resolve_principal)
    props["sidhistory"] = sids

    return {
        "Properties": props,
        "PrimaryGroupSID": None,
        "AllowedToDelegate": resolve_allowed_to_delegate(record, dump, resolve_principal),
        "AllowedToAct": resolve_allowed_to_act(record, resolve_principal),
        "HasSIDHistory": principals,
        "UnconstrainedDelegation": uac_has(uac, "TRUSTED_FOR_DELEGATION"),
        "IsDC": uac_has(uac, "SERVER_TRUST_ACCOUNT"),
        "Sessions": {"Results": [], "Collected": False, "FailureReason": None},
        "PrivilegedSessions": {"Results": [], "Collected": False, "FailureReason": None},
        "RegistrySessions": {"Results": [], "Collected": False, "FailureReason": None},
        "LocalGroups": [],
        "UserRights": [],
        "Status": None,
    }


def read_group_properties(record: dict, dump: LdeepDump, resolve_principal: ResolvePrincipal) -> dict:
    props = _common_props(record)
    props["admincount"] = bool(record.get("adminCount"))
    sids, principals = sid_history(record, resolve_principal)
    props["sidhistory"] = sids

    members = []
    for member_dn in as_list(record.get("member")):
        found = dump.resolve_dn(member_dn)
        if found and found[0].get("objectSid"):
            obj_id, obj_type = resolve_principal(found[0]["objectSid"])
            members.append({"ObjectIdentifier": obj_id, "ObjectType": obj_type})
        else:
            members.append({"ObjectIdentifier": member_dn.upper(), "ObjectType": C.LABEL_BASE})

    return {
        "Properties": props,
        "Members": members,
        "HasSIDHistory": principals,
    }


def read_domain_properties(record: dict) -> dict:
    props = _common_props(record)
    behavior_version = record.get("msDS-Behavior-Version")
    try:
        level = int(behavior_version)
    except (TypeError, ValueError):
        level = -1
    props["functionallevel"] = C.DOMAIN_FUNCTIONAL_LEVEL.get(level, "Unknown")
    props["collected"] = True
    return {"Properties": props}


def read_ou_properties(record: dict) -> dict:
    props = _common_props(record)
    props["blocksinheritance"] = str(record.get("gPOptions")) == "1"
    return {"Properties": props}


def read_gpo_properties(record: dict) -> dict:
    props = _common_props(record)
    path = record.get("gPCFileSysPath") or ""
    props["gpcpath"] = path.upper()
    return {"Properties": props}


def gplinks(gplink_value: Optional[str], dump: LdeepDump) -> list[dict]:
    if not gplink_value:
        return []
    out = []
    for chunk in gplink_value.strip("[]").split("]["):
        if not chunk.startswith("LDAP://"):
            continue
        body = chunk[len("LDAP://") :]
        dn, _, status = body.rpartition(";")
        if not dn or status not in ("0", "1", "2", "3"):
            continue
        if status in ("1", "3"):
            continue  # disabled link
        found = dump.resolve_dn(dn)
        if not found:
            continue
        gpo_record, _label = found
        out.append({"GUID": _guid_id(gpo_record), "IsEnforced": status == "2"})
    return out
