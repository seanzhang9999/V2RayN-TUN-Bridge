"""Build the Windows guard console zip from public sources and pinned runtime assets."""
from hashlib import sha256
from pathlib import Path
import os
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = {
    "Country.mmdb": "fe721d5e47d320b2a23db4eafddb796a22026ef01899bbe7007fc0274016e5f4",
    "geoip.dat": "0d5d2ba0c5a5c58027fd1347a6afd57c9470799b6bb3cbc274fd4657ed8de382",
    "geosite.dat": "556c880698ccc141a73f74fc4aac1484e459f90e2321561b59d84dcb32df87cd",
    "MIHOMO_LICENSE.txt": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
    "mihomo.exe": "82cd796a23492f43a71c1ec27e4e5e0b3d58932014da5a36e79ed9b11fee8162",
}
FILES = ("guard-console.pyw", "guard_live.py", "local_access.py", "local_panel.py",
         "tun_activity.py", "xray_direct.py", "outbound-guard-trial.py", "tun-acceptance.py",
         "mihomo-tun.ps1", "tun-watchdog.ps1", "cleanup-tun.ps1", "PortalRelay.cs",
         "LICENSE", "README.md", "README.zh-CN.md", "THIRD_PARTY_NOTICES.md",
         "docs/release-v0.3.4-rc.2.md")


def recover_runtime(archive):
    if sha256(archive.read_bytes()).hexdigest() != "ef49bc8efc69091676e1cd3ec6ba668f7d1351b242cb38d40b51cdc5c103e247":
        raise ValueError("Unexpected v0.2.4 archive digest")
    (ROOT / "runtime").mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as previous:
        for name, digest in RUNTIME.items():
            data = previous.read("V2RayN-TUN-Bridge/_internal/runtime/" + name)
            if sha256(data).hexdigest() != digest:
                raise ValueError("Unexpected runtime digest for " + name)
            (ROOT / "runtime" / name).write_bytes(data)


def build():
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    relay = dist / "PortalRelay.exe"
    csc = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    subprocess.run([str(csc), "/nologo", "/target:winexe", "/platform:x64",
                    "/out:" + str(relay), str(ROOT / "PortalRelay.cs")], check=True)
    bundle = dist / "V2RayN-TUN-Bridge-v0.3.4-rc.2-windows-x64.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zipped:
        for name in FILES:
            zipped.write(ROOT / name, name)
        for source in sorted((ROOT / "src").rglob("*.py")):
            zipped.write(source, source.relative_to(ROOT))
        for name, digest in RUNTIME.items():
            data = (ROOT / "runtime" / name).read_bytes()
            if sha256(data).hexdigest() != digest:
                raise ValueError("Unexpected runtime digest for " + name)
            zipped.writestr("runtime/" + name, data)
        zipped.write(relay, relay.name)
    with zipfile.ZipFile(bundle) as zipped:
        if zipped.testzip():
            raise ValueError("Invalid release archive")
    (dist / "SHA256SUMS.txt").write_text(sha256(bundle.read_bytes()).hexdigest() + "  " + bundle.name + "\n", encoding="ascii")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        recover_runtime(Path(sys.argv[1]))
    else:
        build()
