#!/usr/bin/env python3
"""Verify the newest public hash-only issuance receipt without signal plaintext."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


INDEX_SCHEMA = "defire_signal_issuance_index_v2"
COMMITMENT_SCHEMA = "defire_signal_issuance_commitment_v2"
OTS_PACKAGE = "opentimestamps@0.4.9"
ROOT_SHA256 = "b52fae9cd8dcf49285f0337cd815deca13fedd31f653bf07f61579451517e18c"
MAX_DELAY_SECONDS = 300
SHA256 = re.compile(r"^[0-9a-f]{64}$")
INDEX_TOP = {
    "schema_version", "updated_at", "event_count", "last_issuance_sequence",
    "last_issuance_sha256", "events",
}
COMMITMENT_KEYS = {
    "schema_version", "issuance_sequence", "issued_at", "submitted_at",
    "submission_delay_seconds", "row_sha256", "issuance_sha256",
    "previous_issuance_sha256", "hash_algorithm", "timestamp_protocol",
}
EVENT_KEYS = COMMITMENT_KEYS | {
    "commitment_sha256", "timestamp_status", "bitcoin_block_height",
    "rfc3161_tsa", "rfc3161_time", "rfc3161_delay_seconds",
    "rfc3161_response_sha256", "commitment_url", "proof_url", "signed_time_url",
}


class VerificationError(ValueError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()


def load_canonical(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict) or raw != canonical(value):
        raise VerificationError(f"{label} is not canonical JSON")
    return value, raw


def required_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise VerificationError(f"{label} is not SHA-256")
    return value


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerificationError(f"{label} is not UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise VerificationError(f"{label} is invalid") from exc


def run(command: list[str], label: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"{label} could not run: {exc}") from exc
    output = result.stdout.strip()
    if result.returncode != 0:
        raise VerificationError(f"{label} failed with exit {result.returncode}: {output}")
    return output


def fetch(url: str, path: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "DeFIRE-independent-verifier/1"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200:
                raise VerificationError(f"download returned HTTP {response.status}: {url}")
            path.write_bytes(response.read())
    except OSError as exc:
        raise VerificationError(f"download failed: {url}: {exc}") from exc


def validate_index(index: dict[str, Any], raw: bytes) -> list[dict[str, Any]]:
    if set(index) != INDEX_TOP or index.get("schema_version") != INDEX_SCHEMA:
        raise VerificationError("issuance index schema is invalid")
    if raw != canonical(index):
        raise VerificationError("issuance index is not canonical JSON")
    events = index.get("events")
    if not isinstance(events, list) or index.get("event_count") != len(events):
        raise VerificationError("issuance index count is invalid")
    previous = None
    for sequence, event in enumerate(events, start=1):
        if not isinstance(event, dict) or set(event) != EVENT_KEYS:
            raise VerificationError(f"issuance event {sequence} schema is invalid")
        if event.get("issuance_sequence") != sequence:
            raise VerificationError(f"issuance sequence gap at {sequence}")
        if event.get("previous_issuance_sha256") != previous:
            raise VerificationError(f"issuance chain is broken at {sequence}")
        for key in ("row_sha256", "issuance_sha256", "commitment_sha256", "rfc3161_response_sha256"):
            required_sha(event.get(key), f"issuance event {sequence} {key}")
        previous = event["issuance_sha256"]
    expected_sequence = len(events) if events else None
    if index.get("last_issuance_sequence") != expected_sequence:
        raise VerificationError("issuance index last sequence is invalid")
    if index.get("last_issuance_sha256") != previous:
        raise VerificationError("issuance index chain head is invalid")
    return events


def parse_rfc3161_time(output: str) -> datetime:
    if not re.search(r"^Status:\s+Granted\.\s*$", output, re.MULTILINE):
        raise VerificationError("RFC 3161 response was not granted")
    if not re.search(r"^Hash Algorithm:\s+sha256\s*$", output, re.MULTILINE):
        raise VerificationError("RFC 3161 response does not use SHA-256")
    match = re.search(
        r"^Time stamp:\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT\s*$",
        output,
        re.MULTILINE,
    )
    months = {name: number for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )}
    if not match or match.group(1) not in months:
        raise VerificationError("RFC 3161 response has no parseable UTC timestamp")
    return datetime(
        int(match.group(6)), months[match.group(1)], int(match.group(2)),
        int(match.group(3)), int(match.group(4)), int(match.group(5)), tzinfo=timezone.utc,
    )


def verify_latest(
    event: dict[str, Any], base_url: str, root: Path, openssl: str, ots: str,
) -> str:
    sequence = event["issuance_sequence"]
    directory = f"{sequence:020d}"
    expected_urls = {
        "commitment_url": f"{directory}/commitment.json",
        "proof_url": f"{directory}/commitment.json.ots",
        "signed_time_url": f"{directory}/commitment.json.tsr",
    }
    for key, expected in expected_urls.items():
        if event.get(key) != expected:
            raise VerificationError(f"issuance event {sequence} {key} is invalid")
    if sha256(root.read_bytes()) != ROOT_SHA256:
        raise VerificationError("DigiCert root differs from the pinned root")

    with tempfile.TemporaryDirectory(prefix="defire-public-issuance-") as temp:
        work = Path(temp)
        commitment_path = work / "commitment.json"
        proof_path = work / "commitment.json.ots"
        response_path = work / "commitment.json.tsr"
        for key, path in (
            ("commitment_url", commitment_path),
            ("proof_url", proof_path),
            ("signed_time_url", response_path),
        ):
            fetch(f"{base_url.rstrip('/')}/{event[key]}", path)

        commitment, commitment_raw = load_canonical(commitment_path, "issuance commitment")
        if set(commitment) != COMMITMENT_KEYS or commitment.get("schema_version") != COMMITMENT_SCHEMA:
            raise VerificationError("issuance commitment schema is invalid")
        for key in COMMITMENT_KEYS:
            if commitment.get(key) != event.get(key):
                raise VerificationError(f"issuance commitment differs from index at {key}")
        if sha256(commitment_raw) != event["commitment_sha256"]:
            raise VerificationError("issuance commitment hash differs from index")
        if sha256(response_path.read_bytes()) != event["rfc3161_response_sha256"]:
            raise VerificationError("RFC 3161 response hash differs from index")
        if commitment.get("hash_algorithm") != "SHA-256" \
          or commitment.get("timestamp_protocol") != "OpenTimestamps-Bitcoin+RFC3161-DigiCert":
            raise VerificationError("issuance commitment algorithms are invalid")
        if isinstance(commitment.get("submission_delay_seconds"), bool) \
          or not isinstance(commitment.get("submission_delay_seconds"), int):
            raise VerificationError("issuance submission delay type is invalid")

        issued_at = parse_utc(commitment["issued_at"], "issued_at")
        submitted_at = parse_utc(commitment["submitted_at"], "submitted_at")
        submission_delay = int((submitted_at - issued_at).total_seconds())
        if submission_delay < 0 or submission_delay != commitment["submission_delay_seconds"]:
            raise VerificationError("issuance submission delay is invalid")

        reply = run([openssl, "ts", "-reply", "-in", str(response_path), "-text"], "RFC 3161 reply")
        trusted_at = parse_rfc3161_time(reply)
        verified = run(
            [
                openssl, "ts", "-verify", "-data", str(commitment_path),
                "-in", str(response_path), "-CAfile", str(root),
                "-attime", str(int(trusted_at.timestamp())),
            ],
            "RFC 3161 verification",
        )
        if "Verification: OK" not in verified:
            raise VerificationError("RFC 3161 signature did not verify")
        trusted_text = trusted_at.isoformat().replace("+00:00", "Z")
        delay = int((trusted_at - issued_at).total_seconds())
        if trusted_text != event["rfc3161_time"] or delay != event["rfc3161_delay_seconds"]:
            raise VerificationError("RFC 3161 signed time differs from index")
        if delay < 0 or delay > MAX_DELAY_SECONDS:
            raise VerificationError(f"BACKDATE CHECK FAILED: signed-time delay is {delay}s")
        if event.get("rfc3161_tsa") != "DigiCert RFC 3161":
            raise VerificationError("RFC 3161 authority is invalid")

        ots_prefix = [ots, "--yes", OTS_PACKAGE] if ots == "npx" else [ots]
        info = run([*ots_prefix, "info", str(proof_path)], "OpenTimestamps info")
        digest = re.search(r"File sha256 hash:\s*([0-9a-f]{64})", info)
        if not digest or digest.group(1) != event["commitment_sha256"]:
            raise VerificationError("OpenTimestamps proof targets another commitment")
        status = event.get("timestamp_status")
        if status == "bitcoin_anchored":
            output = run(
                [*ots_prefix, "verify", "-i", "-t", "10000", str(proof_path), "-f", str(commitment_path)],
                "OpenTimestamps Bitcoin verification",
            )
            if "Success! Bitcoin block" not in output or event.get("bitcoin_block_height") is None:
                raise VerificationError("Bitcoin verification receipt is invalid")
        elif status == "awaiting_bitcoin":
            if "PendingAttestation" not in info or event.get("bitcoin_block_height") is not None:
                raise VerificationError("pending OpenTimestamps receipt is invalid")
        else:
            raise VerificationError("OpenTimestamps status is invalid")
    return f"AT-SIGNAL PASS: {len_text(sequence)}; newest DigiCert delay {delay}s; {status}"


def len_text(sequence: int) -> str:
    noun = "receipt" if sequence == 1 else "receipts"
    return f"{sequence} gap-free hash-only {noun}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--ots", default="npx")
    args = parser.parse_args()
    try:
        index, raw = load_canonical(args.index, "issuance index")
        events = validate_index(index, raw)
        if not events:
            print("AT-SIGNAL PENDING: no public hash receipt exists yet")
            return 0
        print(verify_latest(events[-1], args.base_url, args.root, args.openssl, args.ots))
        return 0
    except (OSError, VerificationError) as exc:
        print(f"AT-SIGNAL FAILURE: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
