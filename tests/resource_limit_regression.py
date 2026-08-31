#!/usr/bin/env python3
"""End-to-end checks for bounded APK ZIP handling and JSON diagnostics."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path


def scan(scanner: Path, apk: Path) -> dict:
    process = subprocess.run(
        [str(scanner), str(apk), "--en"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError(
            f"scanner returned {process.returncode} for {apk.name}: "
            f"{process.stderr.decode('utf-8', errors='replace')}"
        )
    try:
        return json.loads(process.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(
            f"scanner did not return valid UTF-8 JSON for {apk.name}: {error}\n"
            f"stdout={process.stdout[:1000]!r}"
        ) from error


def codes(payload: dict) -> set[str]:
    return {item.get("code", "") for item in payload.get("scan_diagnostics", [])}


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    args = parser.parse_args()
    scanner = args.scanner.resolve()

    with tempfile.TemporaryDirectory(prefix="obfuscan-resource-tests-") as temp_dir:
        root = Path(temp_dir)

        ordinary = root / "ordinary.apk"
        with zipfile.ZipFile(ordinary, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("lib/arm64-v8a/libtiny.so", b"\x7fELF" + b"\0" * 124)
        payload = scan(scanner, ordinary)
        expect(payload.get("scan_status") == "OK", "ordinary APK must remain accepted")
        expect(len(payload.get("results", [])) == 1, "ordinary SO must produce one result")

        hap = root / "ordinary.hap"
        with zipfile.ZipFile(hap, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("libs/arm64-v8a/libtiny.so", b"\x7fELF" + b"\0" * 124)
        payload = scan(scanner, hap)
        expect(payload.get("scan_status") == "OK", "ordinary HAP must remain accepted")
        expect(len(payload.get("results", [])) == 1, "HAP libs/ SO must produce one result")

        bomb = root / "compression-bomb.apk"
        with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("lib/arm64-v8a/libbomb.so", b"\0" * (2 * 1024 * 1024))
        payload = scan(scanner, bomb)
        expect(payload.get("scan_status") == "PARTIAL", "compression bomb must be partial")
        expect("SO_COMPRESSION_RATIO_LIMIT" in codes(payload),
               "compression bomb must have an explicit JSON diagnostic")
        expect(payload.get("scan_observed", {}).get("analyzed_so_count") == 0,
               "compression bomb must not be extracted/analyzed")

        too_many_candidates = root / "too-many-candidates.apk"
        with zipfile.ZipFile(too_many_candidates, "w", compression=zipfile.ZIP_STORED) as archive:
            for index in range(257):
                archive.writestr(f"lib/arm64-v8a/lib{index:03d}.so", b"x")
        payload = scan(scanner, too_many_candidates)
        expect(payload.get("scan_status") == "REJECTED", "candidate flood must be rejected")
        expect("SO_CANDIDATE_LIMIT" in codes(payload),
               "candidate flood must have an explicit JSON diagnostic")
        expect(payload.get("scan_observed", {}).get("analyzed_so_count") == 0,
               "candidate flood must be rejected before extraction")

        too_many_entries = root / "too-many-entries.apk"
        with zipfile.ZipFile(too_many_entries, "w", compression=zipfile.ZIP_STORED) as archive:
            for index in range(20001):
                archive.writestr(f"res/raw/e{index:05d}", b"")
        payload = scan(scanner, too_many_entries)
        expect(payload.get("scan_status") == "REJECTED", "ZIP entry flood must be rejected")
        expect("APK_ENTRY_LIMIT" in codes(payload),
               "ZIP entry flood must have an explicit JSON diagnostic")

        malformed = root / "malformed.apk"
        malformed.write_bytes(b"this is not a ZIP archive")
        payload = scan(scanner, malformed)
        expect(payload.get("scan_status") == "ERROR", "malformed APK must report an input error")
        expect("APK_OPEN_FAILED" in codes(payload),
               "malformed APK must return an explicit JSON diagnostic")

    print("resource_limit_regression: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
