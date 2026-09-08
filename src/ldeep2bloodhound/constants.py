"""BloodHound-specific constants: ADRights bitmasks, extended-rights GUIDs,
well-known SIDs, and the various AD flag tables. Values for the AD-standard
bitmasks/GUIDs are taken from ldeep's own constants module (ldeep.views.constants)
since ldeep already decodes userAccountControl/groupType/trustAttributes/etc.
into the same canonical tables SharpHound relies on.
"""

from ldeep.views.constants import (  # noqa: F401
    EXTENDED_RIGHTS_MAP,
    FOREST_LEVELS,
    GROUP_TYPE,
    KERBEROS_ENC_TYPE,
    SAM_ACCOUNT_TYPE,
    TRUSTS_INFOS,
    USER_ACCOUNT_CONTROL,
    WELL_KNOWN_SIDS,
    ADRights,
)

# ---------------------------------------------------------------------------
# userAccountControl bit values (mirrors ldeep's table, kept as ints here
# because we need to test bits directly rather than substring-match the
# decoded "A | B | C" string ldeep produces).
# ---------------------------------------------------------------------------
UF_SCRIPT = 0x0001
UF_ACCOUNTDISABLE = 0x0002
UF_LOCKOUT = 0x0010
UF_PASSWD_NOTREQD = 0x0020
UF_PASSWD_CANT_CHANGE = 0x0040
UF_NORMAL_ACCOUNT = 0x0200
UF_INTERDOMAIN_TRUST_ACCOUNT = 0x0800
UF_WORKSTATION_TRUST_ACCOUNT = 0x1000
UF_SERVER_TRUST_ACCOUNT = 0x2000
UF_DONT_EXPIRE_PASSWD = 0x10000
UF_SMARTCARD_REQUIRED = 0x40000
UF_TRUSTED_FOR_DELEGATION = 0x80000
UF_NOT_DELEGATED = 0x100000
UF_USE_DES_KEY_ONLY = 0x200000
UF_DONT_REQUIRE_PREAUTH = 0x400000
UF_PASSWORD_EXPIRED = 0x800000
UF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000

UAC_COMPUTER_ACCOUNT_BITS = (
    UF_WORKSTATION_TRUST_ACCOUNT
    | UF_SERVER_TRUST_ACCOUNT
    | UF_INTERDOMAIN_TRUST_ACCOUNT
    | UF_PARTIAL_SECRETS_ACCOUNT
)

# msDS-SupportedEncryptionTypes bit -> name (KERBEROS_ENC_TYPE has the same
# values but ldeep decodes the attribute to a "A | B" string already; kept
# here for reference / fallback parsing of raw ints).
ENC_RC4 = 0x00000004
ENC_AES128 = 0x00000008
ENC_AES256 = 0x00000010

# groupType bits
GROUP_TYPE_SECURITY_ENABLED = 0x80000000

# sAMAccountType values that represent groups (used to disambiguate FSPs /
# objects without objectClass hints).
SAM_GROUP_TYPES = {
    0x10000000,
    0x10000001,
    0x20000000,
    0x20000001,
    0x40000000,
    0x40000001,
}

# ---------------------------------------------------------------------------
# BloodHound "Label" values used as PrincipalType / ObjectType.
# ---------------------------------------------------------------------------
LABEL_USER = "User"
LABEL_GROUP = "Group"
LABEL_COMPUTER = "Computer"
LABEL_DOMAIN = "Domain"
LABEL_OU = "OU"
LABEL_GPO = "GPO"
LABEL_CONTAINER = "Container"
LABEL_BASE = "Base"

# ---------------------------------------------------------------------------
# ACE rights: SharpHound's ACLProcessor emits these RightName strings.
# ---------------------------------------------------------------------------
RIGHT_ALL_EXTENDED_RIGHTS = "AllExtendedRights"
RIGHT_GENERIC_ALL = "GenericAll"
RIGHT_GENERIC_WRITE = "GenericWrite"
RIGHT_WRITE_DACL = "WriteDacl"
RIGHT_WRITE_OWNER = "WriteOwner"
RIGHT_OWNS = "Owns"
RIGHT_ADD_MEMBER = "AddMember"
RIGHT_ADD_SELF = "AddSelf"
RIGHT_FORCE_CHANGE_PASSWORD = "ForceChangePassword"
RIGHT_ALLOWED_TO_ACT = "AddAllowedToAct"
RIGHT_WRITE_SPN = "WriteSPN"
RIGHT_ADD_KEY_CREDENTIAL_LINK = "AddKeyCredentialLink"
RIGHT_READ_LAPS_PASSWORD = "ReadLAPSPassword"
RIGHT_READ_GMSA_PASSWORD = "ReadGMSAPassword"
RIGHT_WRITE_ACCOUNT_RESTRICTIONS = "WriteAccountRestrictions"
RIGHT_DC_SYNC = "DCSync"
RIGHT_GET_CHANGES = "GetChanges"
RIGHT_GET_CHANGES_ALL = "GetChangesAll"

# Object-type ACE "ObjectType" GUIDs that map to a specific edge instead of a
# generic ExtendedRight/WriteProperty/ValidatedWrite edge.
GUID_USER_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_SELF_MEMBERSHIP = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_DS_VALIDATED_WRITE_COMPUTER = "9b026da6-0d3c-465c-8bee-5199d7165cba"
GUID_VALIDATED_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"
GUID_MEMBERSHIP_PROPERTY_SET = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
GUID_WRITE_GPLINK = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
GUID_WRITE_ALT_SECURITY_IDENTITIES = "00fbf30c-91fe-11d1-aebc-0000f80367c1"
GUID_WRITE_PUBLIC_INFORMATION = "e48d0154-bcf8-11d1-8702-00c04fb96050"
GUID_ALL_EXTENDED_RIGHTS = "00000000-0000-0000-0000-000000000000"
GUID_ALL_ATTRIBUTES = "00000000-0000-0000-0000-000000000000"

RIGHT_WRITE_GPLINK = "WriteGPLink"
RIGHT_WRITE_ALT_SECURITY_IDENTITIES = "WriteAltSecurityIdentities"
RIGHT_WRITE_PUBLIC_INFORMATION = "WritePublicInformation"
RIGHT_GET_CHANGES_IN_FILTERED_SET = "GetChangesInFilteredSet"

# Attribute schemaIDGUIDs relevant to specific WriteProperty edges.
GUID_ATTR_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_ATTR_SERVICE_PRINCIPAL_NAME = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GUID_ATTR_MS_DS_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
GUID_ATTR_MS_DS_ALLOWED_TO_ACT_ON_BEHALF = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
GUID_ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"

WELL_KNOWN_LOCAL_SID_SUFFIXES = {
    "S-1-5-32-544",
    "S-1-5-32-545",
    "S-1-5-32-546",
    "S-1-5-32-547",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
    "S-1-5-32-554",
    "S-1-5-32-555",
    "S-1-5-32-556",
    "S-1-5-32-557",
    "S-1-5-32-558",
    "S-1-5-32-559",
    "S-1-5-32-560",
    "S-1-5-32-561",
    "S-1-5-32-562",
    "S-1-5-32-569",
    "S-1-5-32-573",
    "S-1-5-32-574",
    "S-1-5-32-575",
    "S-1-5-32-576",
    "S-1-5-32-577",
    "S-1-5-32-578",
    "S-1-5-32-579",
    "S-1-5-32-580",
}

# Well-known RIDs that mark a group as "high value" in BloodHound.
HIGH_VALUE_RIDS = {
    "-512",  # Domain Admins
    "-516",  # Domain Controllers
    "-518",  # Schema Admins
    "-519",  # Enterprise Admins
    "-544",  # Administrators
    "-548",  # Account Operators
    "-549",  # Server Operators
    "-550",  # Print Operators
    "-551",  # Backup Operators
}

FUNCTIONAL_LEVEL_MAP = FOREST_LEVELS

# msDS-Behavior-Version (domain functional level) -> BloodHound's "functionallevel"
# string, from SharpHoundCommon LdapPropertyProcessor.cs::FunctionalLevelToString.
DOMAIN_FUNCTIONAL_LEVEL = {
    0: "2000 Mixed/Native",
    1: "2003 Interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
    8: "2025",
}

# ---------------------------------------------------------------------------
# Schema class base GUIDs, keyed by BloodHound Label. An object-type ACE only
# applies to an object if its "Inherited Object Type" GUID is absent or equals
# this table's entry for the object's own class.
# Source: SharpHoundCommon ACLProcessor.cs static BaseGuids table (verified).
# ---------------------------------------------------------------------------
BASE_CLASS_GUIDS = {
    LABEL_USER: "bf967aba-0de6-11d0-a285-00aa003049e2",
    LABEL_COMPUTER: "bf967a86-0de6-11d0-a285-00aa003049e2",
    LABEL_GROUP: "bf967a9c-0de6-11d0-a285-00aa003049e2",
    LABEL_DOMAIN: "19195a5a-6da0-11d0-afd3-00c04fd930c9",
    LABEL_GPO: "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
    LABEL_OU: "bf967aa5-0de6-11d0-a285-00aa003049e2",
    LABEL_CONTAINER: "bf967a8b-0de6-11d0-a285-00aa003049e2",
}

# ---------------------------------------------------------------------------
# Well-known SIDs: name + BloodHound Label, from SharpHoundCommonLib's
# WellKnownPrincipal.cs (verified against the actual source, not memory).
# Object identifier for these is f"{domain_fqdn}-{sid}".upper(), except
# S-1-5-9 (Enterprise Domain Controllers) which is forest-scoped.
# ---------------------------------------------------------------------------
FOREST_SCOPED_WELL_KNOWN_SIDS = {"S-1-5-9"}

WELL_KNOWN_PRINCIPALS = {
    "S-1-0": ("Null Authority", LABEL_USER),
    "S-1-0-0": ("Nobody", LABEL_USER),
    "S-1-1": ("World Authority", LABEL_USER),
    "S-1-1-0": ("Everyone", LABEL_GROUP),
    "S-1-2": ("Local Authority", LABEL_USER),
    "S-1-2-0": ("Local", LABEL_GROUP),
    "S-1-2-1": ("Console Logon", LABEL_GROUP),
    "S-1-3": ("Creator Authority", LABEL_USER),
    "S-1-3-0": ("Creator Owner", LABEL_USER),
    "S-1-3-1": ("Creator Group", LABEL_GROUP),
    "S-1-3-2": ("Creator Owner Server", LABEL_COMPUTER),
    "S-1-3-3": ("Creator Group Server", LABEL_COMPUTER),
    "S-1-3-4": ("Owner Rights", LABEL_GROUP),
    "S-1-4": ("Non-unique Authority", LABEL_USER),
    "S-1-5": ("NT Authority", LABEL_USER),
    "S-1-5-1": ("Dialup", LABEL_GROUP),
    "S-1-5-2": ("Network", LABEL_GROUP),
    "S-1-5-3": ("Batch", LABEL_GROUP),
    "S-1-5-4": ("Interactive", LABEL_GROUP),
    "S-1-5-6": ("Service", LABEL_GROUP),
    "S-1-5-7": ("Anonymous", LABEL_GROUP),
    "S-1-5-8": ("Proxy", LABEL_GROUP),
    "S-1-5-9": ("Enterprise Domain Controllers", LABEL_GROUP),
    "S-1-5-10": ("Principal Self", LABEL_USER),
    "S-1-5-11": ("Authenticated Users", LABEL_GROUP),
    "S-1-5-12": ("Restricted Code", LABEL_GROUP),
    "S-1-5-13": ("Terminal Server Users", LABEL_GROUP),
    "S-1-5-14": ("Remote Interactive Logon", LABEL_GROUP),
    "S-1-5-15": ("This Organization", LABEL_GROUP),
    "S-1-5-17": ("IUSR", LABEL_USER),
    "S-1-5-18": ("Local System", LABEL_USER),
    "S-1-5-19": ("Local Service", LABEL_USER),
    "S-1-5-20": ("Network Service", LABEL_USER),
    "S-1-5-21-0-0-0-496": ("Compounded Authentication", LABEL_GROUP),
    "S-1-5-21-0-0-0-497": ("Claims Valid", LABEL_GROUP),
    "S-1-5-32-544": ("Administrators", LABEL_GROUP),
    "S-1-5-32-545": ("Users", LABEL_GROUP),
    "S-1-5-32-546": ("Guests", LABEL_GROUP),
    "S-1-5-32-547": ("Power Users", LABEL_GROUP),
    "S-1-5-32-548": ("Account Operators", LABEL_GROUP),
    "S-1-5-32-549": ("Server Operators", LABEL_GROUP),
    "S-1-5-32-550": ("Print Operators", LABEL_GROUP),
    "S-1-5-32-551": ("Backup Operators", LABEL_GROUP),
    "S-1-5-32-552": ("Replicators", LABEL_GROUP),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", LABEL_GROUP),
    "S-1-5-32-555": ("Remote Desktop Users", LABEL_GROUP),
    "S-1-5-32-556": ("Network Configuration Operators", LABEL_GROUP),
    "S-1-5-32-557": ("Incoming Forest Trust Builders", LABEL_GROUP),
    "S-1-5-32-558": ("Performance Monitor Users", LABEL_GROUP),
    "S-1-5-32-559": ("Performance Log Users", LABEL_GROUP),
    "S-1-5-32-560": ("Windows Authorization Access Group", LABEL_GROUP),
    "S-1-5-32-561": ("Terminal Server License Servers", LABEL_GROUP),
    "S-1-5-32-562": ("Distributed COM Users", LABEL_GROUP),
    "S-1-5-32-568": ("IIS_IUSRS", LABEL_GROUP),
    "S-1-5-32-569": ("Cryptographic Operators", LABEL_GROUP),
    "S-1-5-32-573": ("Event Log Readers", LABEL_GROUP),
    "S-1-5-32-574": ("Certificate Service DCOM Access", LABEL_GROUP),
    "S-1-5-32-575": ("RDS Remote Access Servers", LABEL_GROUP),
    "S-1-5-32-576": ("RDS Endpoint Servers", LABEL_GROUP),
    "S-1-5-32-577": ("RDS Management Servers", LABEL_GROUP),
    "S-1-5-32-578": ("Hyper-V Administrators", LABEL_GROUP),
    "S-1-5-32-579": ("Access Control Assistance Operators", LABEL_GROUP),
    "S-1-5-32-580": ("Remote Management Users", LABEL_GROUP),
    "S-1-5-32-581": ("System Managed Accounts Group", LABEL_GROUP),
    "S-1-5-32-582": ("Storage Replica Administrators", LABEL_GROUP),
    "S-1-5-32-583": ("Device Owners", LABEL_GROUP),
    "S-1-5-64-10": ("NTLM Authentication", LABEL_GROUP),
    "S-1-5-64-14": ("Schannel Authentication", LABEL_GROUP),
    "S-1-5-64-21": ("Digest Authentication", LABEL_GROUP),
    "S-1-5-65-1": ("This Organization Certificate", LABEL_GROUP),
    "S-1-5-80": ("Service", LABEL_GROUP),
}

# ---------------------------------------------------------------------------
# Trust attribute bits (MS-ADTS 6.1.6.7.9) and TrustDirection enum values,
# used by acl/build for Domain.Trusts[]. Verified logic against
# SharpHoundCommon DomainTrustProcessor.cs (the .NET-only richer trust-type
# detection via TrustRelationshipInformation isn't available to us, so we use
# the documented attributes-based fallback it falls back to itself).
# ---------------------------------------------------------------------------
TRUST_ATTR_NON_TRANSITIVE = 0x1
TRUST_ATTR_UPLEVEL_ONLY = 0x2
TRUST_ATTR_QUARANTINED_DOMAIN = 0x4
TRUST_ATTR_FOREST_TRANSITIVE = 0x8
TRUST_ATTR_CROSS_ORGANIZATION = 0x10
TRUST_ATTR_WITHIN_FOREST = 0x20
TRUST_ATTR_TREAT_AS_EXTERNAL = 0x40
TRUST_ATTR_USES_RC4_ENCRYPTION = 0x80
TRUST_ATTR_CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x200
TRUST_ATTR_PIM_TRUST = 0x400
TRUST_ATTR_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x800

TRUST_DIRECTION_MAP = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}
