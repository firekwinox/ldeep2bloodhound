# ldeep2bloodhound

Converts an [ldeep](https://github.com/franc-pentest/ldeep) LDAP dump of an Active Directory
domain into a [BloodHound CE](https://github.com/SpecterOps/BloodHound) ingestion zip, including
ACL edges.

```sh
ldeep2bloodhound <ldeep_dump_dir> -o bloodhound.zip
```

Tested with **ldeep 2.0.3** and **BloodHound CE server v9.6.0** (community edition).

## Why this exists

`ldeep` is a fast, flexible LDAP enumeration tool, but its output isn't in a format BloodHound can
ingest. This tool bridges the two: it reads the JSON files ldeep already writes and reshapes them
into the exact schema BloodHound CE's `/api/v2/file-upload` endpoint expects.

## Usage

### Install

```sh
git clone https://github.com/firekwinox/ldeep2bloodhound.git
cd ldeep2bloodhound
python3 -m venv .venv && .venv/bin/pip install -e .
```

Or install the prebuilt wheel from a [release](https://github.com/firekwinox/ldeep2bloodhound/releases):

```sh
python3 -m venv .venv && .venv/bin/pip install https://github.com/firekwinox/ldeep2bloodhound/releases/download/v0.1.0/ldeep2bloodhound-0.1.0-py3-none-any.whl
```

### Collect the data with `ldeep` (with ACLs)

```sh
ldeep --security_desc ldap -u USER -p PASS -d DOMAIN -s ldap://SERVER all <prefix>
```

This embeds a fully-parsed `nTSecurityDescriptor` dict directly into every object's existing JSON
record.

`ldeep` has a light bug where, **inside** that multi-command `all` sweep, the `users` and `groups`
commands' `nTSecurityDescriptor` comes back as an empty list for every record, even though the
exact same command run standalone works fine. This tool's `collect` subcommand works around it by
re-running those two commands standalone right after the main sweep:

```sh
ldeep2bloodhound collect <prefix> -- -d DOMAIN -s ldap://SERVER -u USER -p PASS
```

This just shells out to `ldeep` itself (twice), there's no custom LDAP client here. You can run `ldeep` yourself as well.

### Convert

```sh
# convert
ldeep2bloodhound ldeep/ -o bloodhound.zip

# convert and upload straight to a running BloodHound CE instance
ldeep2bloodhound ldeep/ -o bloodhound.zip \
    --upload --bh-url http://127.0.0.1:8080 --bh-user admin --bh-pass '********'
```

`ldeep2bloodhound <dump_dir> -o out.zip` still works fine without ever running `collect`, it just
produces a zip with empty `Aces` lists (and prints a warning) if the dump has no security
descriptors in it.

## How it works

The conversion logic (`src/ldeep2bloodhound/`) is a from-scratch Python port of the relevant parts
of SharpHound's collector (`SharpHoundCommon`), verified directly against that C# source rather
than reconstructed from memory:

| Module | Responsibility |
|---|---|
| `loader.py` | Reads every `<prefix>__*.json` into one in-memory model, indexed by DN/SID/GUID |
| `acl.py` | Turns each object's parsed security descriptor into BloodHound ACE edges (`GenericAll`, `WriteDacl`, `AddMember`, `ForceChangePassword`, `AddKeyCredentialLink`, `GetChanges`/`GetChangesAll` (DCSync), etc.) |
| `properties.py` | Builds each node's `Properties` dict (UAC-derived flags, timestamps, delegation, SID history, group membership, GPO links, ...) |
| `wellknown.py` | Maps well-known SIDs (Everyone, Authenticated Users, BUILTIN\* groups, ...) to BloodHound's domain-scoped synthetic IDs |
| `build.py` | Orchestrates the above into the 7 BloodHound node-type lists |
| `ingest_zip.py` | Writes the final zip |
| `bhapi.py` | Optional: uploads the zip straight to a BloodHound CE instance via its v2 API |

`constants.py` holds every GUID/rights-bitmask/well-known-SID table used above, each one sourced
from `SharpHoundCommon`'s `ACEGuids.cs`, `ACLProcessor.cs`, and `WellKnownPrincipal.cs`.

## Known limitations

- **No sessions, local admin group membership, or registry-derived data** (SMB signing, NTLM
  settings, LAPS readability, etc.). `ldeep` is LDAP-only; SharpHound gets those over SMB/RPC
  against each host directly. Computer nodes still carry the correct schema shape for these fields
  (`Sessions`, `LocalGroups`, etc.), they're just empty/`Collected: false`.
- **Generic containers aren't emitted as their own nodes.** `ldeep` has no command that enumerates
  plain `container`-class objects (`CN=Users`, `CN=System`, `CN=ForeignSecurityPrincipals`, ...),
  so this tool can't give them a GUID. Objects that would normally sit inside one of those
  containers get attached directly to the Domain node instead, a minor coarsening of the
  container/OU hierarchy, not a data-correctness issue (ACLs and properties on the objects
  themselves are unaffected).
- **`adminsdholderprotected` is not computed.** It requires comparing an object's implicit-ACE hash
  against AdminSDHolder's own hash (`ACLProcessor.cs::CalculateImplicitACLHash`), which needs a live
  AdminSDHolder reference hash this tool doesn't currently compute. Every other ACL-derived property
  (`isaclprotected`, `doesanyacegrantownerrights`, `doesanyinheritedacegrantownerrights`) is
  implemented and verified.
- **Trust-type detection** uses the LDAP-attribute-only fallback logic SharpHound itself falls back
  to when it can't do a live `.NET` `TrustRelationshipInformation` lookup (`WithinForest` →
  `ParentChild`, `ForestTransitive` → `Forest`, else `External`). Untested against a real
  multi-domain/forest trust.
