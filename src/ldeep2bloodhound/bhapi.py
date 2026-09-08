"""Minimal BloodHound CE v2 API client for uploading an ingest zip.
Confirmed flow: login (JWT) -> file-upload/start -> file-upload/{id} (raw zip
body) -> file-upload/{id}/end. Bearer JWT is sufficient auth, no HMAC needed.
"""

from __future__ import annotations

import urllib.error
import urllib.request
import json as _json


def _request(url: str, method: str, token: str | None = None, data: bytes | None = None, content_type: str | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
            return resp.status, (_json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, _json.loads(body)
        except Exception:
            return e.code, body.decode(errors="replace")


def login(base_url: str, username: str, password: str) -> str:
    status, body = _request(
        f"{base_url}/api/v2/login",
        "POST",
        data=_json.dumps({"login_method": "secret", "username": username, "secret": password}).encode(),
        content_type="application/json",
    )
    if status != 200:
        raise RuntimeError(f"Login failed ({status}): {body}")
    return body["data"]["session_token"]


def upload_zip(base_url: str, token: str, zip_path: str) -> None:
    status, body = _request(f"{base_url}/api/v2/file-upload/start", "POST", token=token)
    if status not in (200, 201):
        raise RuntimeError(f"Could not start upload job ({status}): {body}")
    job_id = body["data"]["id"]

    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    status, body = _request(
        f"{base_url}/api/v2/file-upload/{job_id}",
        "POST",
        token=token,
        data=zip_bytes,
        content_type="application/zip",
    )
    if status not in (200, 202):
        raise RuntimeError(f"Upload failed ({status}): {body}")

    status, body = _request(f"{base_url}/api/v2/file-upload/{job_id}/end", "POST", token=token)
    if status not in (200, 202):
        raise RuntimeError(f"Could not finalize upload job ({status}): {body}")
