"""Build, unpack and execute a native release candidate; never publish or tag."""

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import zipfile

if not __debug__:
    raise RuntimeError("Release validation requires assertions; do not use optimized Python")


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          encoding="utf-8", timeout=180, **kwargs).stdout.strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def smoke(binary, output, version):
    """Use only loopback and synthetic credentials; Chrome is tested by regression CI."""
    assert run([str(binary), "--version"]) == "xsscan version " + version
    help_text = run([str(binary), "--help"])
    assert "--browser-request-budget" in help_text and "--include-raw-evidence" in help_text

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            value = parse_qs(parsed.query).get("q", [""])[0]
            reflected = value if parsed.path == "/positive" else html.escape(value)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "session=release-response-canary; HttpOnly")
            self.end_headers()
            self.wfile.write(("<html><body>" + reflected + "</body></html>").encode())

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    results = []
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        common = [str(binary), "--types", "reflected", "--allow-private",
                  "--verify-execution=false", "--silent", "--max-payloads", "20",
                  "--header", "Authorization: Bearer release-request-canary"]
        for fmt in ("json", "html", "markdown", "sarif", "junit"):
            path = output / ("safe." + fmt)
            result = subprocess.run(common + ["--url", base + "/safe?q=x", "--format", fmt,
                                             "--output", str(path)], capture_output=True, timeout=90)
            assert result.returncode == 0 and not result.stdout and not result.stderr, (fmt, result)
            text = path.read_text(encoding="utf-8")
            assert text and "release-request-canary" not in text and "release-response-canary" not in text
            if os.name != "nt":
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
            if fmt == "json":
                data = json.loads(text)
                assert data["SchemaVersion"] == "1.1" and data["Status"] == "completed" and not data["Findings"]
            results.append({"case": "safe-" + fmt, "exit": result.returncode, "credentials_hidden": True})
        for fmt in ("json", "html", "markdown", "sarif", "junit"):
            path = output / ("positive." + fmt)
            result = subprocess.run(common + ["--url", base + "/positive?q=x", "--format", fmt,
                                             "--output", str(path)], capture_output=True, timeout=90)
            assert result.returncode == 2 and not result.stdout and not result.stderr, (fmt, result)
            text = path.read_text(encoding="utf-8")
            assert text and "release-request-canary" not in text and "release-response-canary" not in text
            if fmt == "json":
                data = json.loads(text)
                assert data["Status"] == "completed" and data["Findings"]
                assert not any(f.get("ExecutionVerified") for f in data["Findings"])
            results.append({"case": "positive-" + fmt, "exit": 2, "credentials_hidden": True})
        for name, extra, expected in (("raw-positive", ["--include-raw-evidence"], 2),
                                     ("budget", ["--request-budget", "1"], 1)):
            path = output / (name + ".json")
            result = subprocess.run(common + ["--url", base + "/positive?q=x", "--format", "json", "--output", str(path)] + extra,
                                    capture_output=True, timeout=90)
            assert result.returncode == expected and not result.stdout and not result.stderr, (name, result)
            data = json.loads(path.read_text(encoding="utf-8"))
            if name == "raw-positive":
                assert data["Status"] == "completed" and data["Findings"]
                text = path.read_text(encoding="utf-8")
                assert "release-request-canary" in text and "release-response-canary" in text
                if os.name != "nt":
                    assert stat.S_IMODE(path.stat().st_mode) == 0o600
            else:
                assert data["Status"] != "completed" and data["Issues"]
                assert data["RequestsSent"] <= 1 and "HTTP request budget exhausted" in json.dumps(data["Issues"])
            results.append({"case": name, "exit": result.returncode})
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--goos", required=True)
    parser.add_argument("--goarch", required=True)
    args = parser.parse_args()
    assert args.version == "1.1.5", "Update the release procedure deliberately for a new version"
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    assert not run(["git", "status", "--porcelain", "--untracked-files=no"]), "Tracked source dirty"
    commit = run(["git", "rev-parse", "HEAD"])
    actual = run(["go", "env", "GOOS", "GOARCH", "GOHOSTOS", "GOHOSTARCH"]).splitlines()
    assert actual == [args.goos, args.goarch, args.goos, args.goarch], actual
    key = args.goos + "_" + args.goarch
    output = root / "dist" / "release-candidates" / key
    output.mkdir(parents=True, exist_ok=False)
    bundle = output / "bundle"
    bundle.mkdir()
    binary_name = "xsscan.exe" if args.goos == "windows" else "xsscan"
    binary = bundle / binary_name
    flags = ["-trimpath", "-ldflags", "-s -w -X main.Version=" + args.version]
    run(["go", "build", *flags, "-o", str(binary), "./cmd"], env=dict(os.environ, CGO_ENABLED="0"))
    metadata = {"version": args.version, "source_commit": commit, "go_version": run(["go", "version"]),
                "python_version": sys.version,
                "goos": args.goos, "goarch": args.goarch, "cgo_enabled": False,
                "build_flags": flags, "binary_sha256": digest(binary)}
    (bundle / "BUILDINFO.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    for name in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(root / name, bundle / name)
    names = sorted(p.name for p in bundle.iterdir())
    archive = output / ("xsscan_" + args.version + "_" + key + (".zip" if args.goos == "windows" else ".tar.gz"))
    if args.goos == "windows":
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
            for name in names:
                zipped.write(bundle / name, name)
    else:
        with tarfile.open(archive, "w:gz") as tar:
            for name in names:
                info = tar.gettarinfo(str(bundle / name), arcname=name)
                info.mode = 0o755 if name == binary_name else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with (bundle / name).open("rb") as file:
                    tar.addfile(info, file)
    # Execute the archive's extracted bytes, not just the build directory.
    with tempfile.TemporaryDirectory(prefix="xsscan-release-") as tmp:
        extracted = Path(tmp)
        if args.goos == "windows":
            with zipfile.ZipFile(archive) as zipped:
                assert zipped.testzip() is None and sorted(zipped.namelist()) == names
                zipped.extractall(extracted)
        else:
            with tarfile.open(archive) as tar:
                assert sorted(tar.getnames()) == names
                assert tar.getmember(binary_name).mode == 0o755
                tar.extractall(extracted, filter="data")
        assert digest(extracted / binary_name) == metadata["binary_sha256"]
        assert all((extracted / name).read_bytes() == (bundle / name).read_bytes() for name in names)
        assert json.loads((extracted / "BUILDINFO.json").read_text(encoding="utf-8")) == metadata
        metadata["runtime_checks"] = smoke(extracted / binary_name, extracted, args.version)
    assets = [archive]
    if args.goos == "windows":
        standalone = output / ("xsscan_" + args.version + "_windows_amd64.exe")
        shutil.copyfile(binary, standalone)
        assert digest(standalone) == metadata["binary_sha256"]
        assert run([str(standalone), "--version"]) == "xsscan version " + args.version
        assets.append(standalone)
    metadata["assets"] = {p.name: {"sha256": digest(p), "size": p.stat().st_size} for p in assets}
    (output / "validation.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
