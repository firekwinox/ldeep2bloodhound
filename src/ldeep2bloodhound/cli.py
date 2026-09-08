from __future__ import annotations

import argparse
import logging
import subprocess
import sys

from .build import build_graph
from .ingest_zip import write_zip


def _cmd_convert(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        nodes = build_graph(args.dump_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    write_zip(nodes, args.output)
    total = sum(len(v) for v in nodes.values())
    print(f"Wrote {args.output} ({total} objects across {len(nodes)} types)")

    if args.upload:
        from . import bhapi

        token = bhapi.login(args.bh_url, args.bh_user, args.bh_pass)
        bhapi.upload_zip(args.bh_url, token, args.output)
        print(f"Uploaded {args.output} to {args.bh_url}")
    return 0


def _cmd_collect(args: argparse.Namespace) -> int:
    cmd = ["ldeep", "--security_desc", "-o", f"{args.prefix}.log", "ldap", *args.ldeep_args, "all", args.prefix]
    print("+ " + " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        return rc

    # Known ldeep bug: within the multi-command `all` sweep, the `users`
    # command's nTSecurityDescriptor comes back as an empty list for every
    # user (verified live: querying `users` standalone with the exact same
    # flags returns it correctly). Re-run just that command to fix it up.
    users_file = f"{args.prefix}__users_all.json"
    print(f"+ re-fetching {users_file} standalone (works around an ldeep bug in the `all` sweep)")
    fix_cmd = [
        "ldeep",
        "--security_desc",
        "-o",
        users_file,
        "ldap",
        *args.ldeep_args,
        "users",
        "all",
        "-v",
    ]
    return subprocess.call(fix_cmd)


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # `collect` is a distinct sub-command; everything else is the bare
    # `ldeep2bloodhound <dump_dir> -o out.zip` conversion invocation.
    if argv and argv[0] == "collect":
        collect = argparse.ArgumentParser(prog="ldeep2bloodhound collect")
        collect.add_argument("prefix", help="ldeep output file prefix to write (also used as the AD dump prefix)")
        collect.add_argument(
            "ldeep_args",
            nargs=argparse.REMAINDER,
            help="Args passed through to `ldeep ldap` (e.g. -- -d DOMAIN -s ldap://SERVER -u USER -p PASS)",
        )
        args = collect.parse_args(argv[1:])
        if args.ldeep_args and args.ldeep_args[0] == "--":
            args.ldeep_args = args.ldeep_args[1:]
        return _cmd_collect(args)

    convert = argparse.ArgumentParser(
        prog="ldeep2bloodhound",
        description="Convert an ldeep LDAP dump into a BloodHound CE ingestion zip.",
    )
    convert.add_argument("dump_dir", help="Directory containing the ldeep dump")
    convert.add_argument("-o", "--output", required=True, help="Output BloodHound ingest zip path")
    convert.add_argument("--upload", action="store_true", help="Upload the zip to BloodHound CE after building it")
    convert.add_argument("--bh-url", default="http://127.0.0.1:8080")
    convert.add_argument("--bh-user", default="admin")
    convert.add_argument("--bh-pass")
    args = convert.parse_args(argv)
    return _cmd_convert(args)


if __name__ == "__main__":
    raise SystemExit(main())
