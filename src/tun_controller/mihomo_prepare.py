"""Prepare private, offline-validated Mihomo configurations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from tun_bridge.resources import resource_path
from tun_controller.mihomo_builder import (
    MihomoBuildError,
    build_mihomo_config,
    build_mihomo_safe_summary,
)
from tun_controller.network_monitor import detect_network_signature
from tun_controller.proxy_endpoint import resolve_proxy_server_ipv4
from tun_controller.v2rayn_source import DEFAULT_APP_ROOT, load_v2rayn_config


MODES = ("mixed-only", "single-address-tun", "full-ipv4-tun")
FILENAMES = {
    "mixed-only": "mihomo-mixed-config.json",
    "single-address-tun": "mihomo-single-config.json",
    "full-ipv4-tun": "mihomo-full-config.json",
}
DEFAULT_CORE_SOURCE = resource_path("runtime", "mihomo.exe")
DEFAULT_GEO_SOURCE = resource_path("runtime")
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def prepare_mihomo_configs(
    output_dir: Path,
    app_root: Path,
    *,
    core_source: Path = DEFAULT_CORE_SOURCE,
    geo_source: Path = DEFAULT_GEO_SOURCE,
    network_signature=None,
    profile_id: str | None = None,
    mixed_port: int = 1082,
    controller_port: int | None = None,
    controller_secret: str = "",
) -> dict[str, object]:
    imported = load_v2rayn_config(app_root, profile_id=profile_id)
    signature = network_signature or detect_network_signature(
        imported.profile.address,
        resolver=lambda host: resolve_proxy_server_ipv4(
            host, imported.profile.port, app_root
        ),
    )
    if signature is None:
        raise MihomoBuildError("No physical IPv4 default route is available")

    output_dir.mkdir(parents=True, exist_ok=True)
    core_path = output_dir / "mihomo-controller.exe"
    _copy_verified(core_source, core_path)
    for name in ("geosite.dat", "geoip.dat", "Country.mmdb"):
        _copy_verified(geo_source / name, output_dir / name)

    summaries: dict[str, object] = {}
    written: list[Path] = []
    try:
        for mode in MODES:
            config = build_mihomo_config(
                imported,
                signature,
                mode=mode,
                mixed_port=mixed_port,
                controller_port=controller_port,
                controller_secret=controller_secret,
            )
            destination = output_dir / FILENAMES[mode]
            temporary = destination.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            os.replace(temporary, destination)
            written.append(destination)
            _validate(core_path, output_dir, destination)
            summaries[mode] = build_mihomo_safe_summary(imported, config)
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise

    return {
        "success": True,
        "core_version": _version(core_path),
        "core_sha256": _sha256(core_path),
        "interface_name": signature.interface_name,
        "modes": summaries,
    }


def _copy_verified(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise MihomoBuildError(f"Required Mihomo runtime asset is missing: {source.name}")
    if destination.is_file() and _sha256(source) == _sha256(destination):
        return
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    shutil.copy2(source, temporary)
    if _sha256(source) != _sha256(temporary):
        temporary.unlink(missing_ok=True)
        raise MihomoBuildError("A copied Mihomo runtime asset failed verification")
    os.replace(temporary, destination)


def _validate(core: Path, data_dir: Path, config: Path) -> None:
    completed = subprocess.run(
        [str(core), "-t", "-d", str(data_dir), "-f", str(config)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    if completed.returncode != 0:
        raise MihomoBuildError("Mihomo rejected a generated configuration")


def _version(core: Path) -> str:
    completed = subprocess.run(
        [str(core), "-v"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "unknown"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--app-root", type=Path, default=DEFAULT_APP_ROOT)
    parser.add_argument("--safe-report", required=True, type=Path)
    parser.add_argument("--profile-id")
    args = parser.parse_args()
    try:
        report = prepare_mihomo_configs(
            args.output_dir, args.app_root, profile_id=args.profile_id
        )
        exit_code = 0
    except Exception as exc:
        report = {
            "success": False,
            "error": "Mihomo offline preparation failed",
            "error_type": type(exc).__name__,
            "safe_detail": str(exc),
        }
        exit_code = 2
    args.safe_report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
