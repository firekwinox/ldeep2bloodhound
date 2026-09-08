"""Writes the BloodHound CE ingest zip: one {"meta":..., "data":[...]} JSON per
node type, zipped flat. Confirmed against real BloodHound CE v9.6.0 fixtures
and the v2 file-upload API (accepts one zip with multiple json entries)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

INGEST_VERSION = 6

_FILENAMES = {
    "users": "users.json",
    "groups": "groups.json",
    "computers": "computers.json",
    "domains": "domains.json",
    "gpos": "gpos.json",
    "ous": "ous.json",
    "containers": "containers.json",
}


def write_zip(nodes: dict[str, list[dict]], output_path: str) -> None:
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for node_type, filename in _FILENAMES.items():
            data = nodes.get(node_type, [])
            payload = {
                "meta": {
                    "methods": 0,
                    "type": node_type,
                    "count": len(data),
                    "version": INGEST_VERSION,
                },
                "data": data,
            }
            zf.writestr(filename, json.dumps(payload))
