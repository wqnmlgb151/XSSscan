"""Repeat real CLI scans against a loopback-only three-parameter fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

if not __debug__:
    raise RuntimeError("Performance validation requires Python assertions")


def validate_report(data):
    """Reject speed measurements obtained with incomplete or missing detection work."""
    modules = {m["type"]: m for m in data["Modules"]}
    coverage = next(c for c in data["coverage"] if c["stage"] == "dom_source_checks")
    assert all(modules[m]["status"] == "completed" for m in ("reflected", "dom", "stored"))
    assert modules["blind"]["status"] == "skipped"
    assert modules["stored"]["requests"] == 20 and modules["stored"]["candidates"] == 3
    assert data["RequestsSent"] == 24 and data["PayloadsSent"] == 9
    assert coverage["planned"] == coverage["started"] == coverage["completed"] == 65
    assert not any(coverage[k] for k in ("failed", "canceled", "not_started"))
    assert any(f["ExecutionVerified"] and f["Parameter"] == "id" for f in data["Findings"])
    return modules, coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", required=True, help="label=executable")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--latency-ms", type=float, default=20)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="store_true", help="separate instrumented diagnostic run")
    parser.add_argument("--resume", action="store_true", help="retain completed samples after interruption")
    args = parser.parse_args()
    if args.rounds < (1 if args.profile else 5) or args.latency_ms < 0:
        parser.error("at least five rounds and nonnegative fixture latency required")
    binaries = {}
    for item in args.binary:
        label, filename = item.split("=", 1)
        if label in binaries or not label.replace("-", "").replace(".", "").isalnum():
            parser.error("unique alphanumeric labels required")
        binaries[label] = Path(filename).resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=args.resume)
    lock = threading.Lock()
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            start = time.perf_counter()
            time.sleep(args.latency_ms / 1000)
            parsed = urlsplit(self.path)
            value = parse_qs(parsed.query).get("id", [""])[0]
            # Only id reflects. The display endpoint deliberately stores nothing.
            body = "<body><a href='/view'>display</a><div>"
            if parsed.path.startswith("/index.php"):
                body += value
            body += "</div><script>window.fixtureReady=true;</script></body>"
            data = body.encode("utf-8")
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except ConnectionError:
                pass
            with lock:
                requests.append({"path": parsed.path, "duration_ms": (time.perf_counter() - start) * 1000})

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    target = f"http://localhost:{server.server_port}/index.php?c=text&a=gywm&id=10"
    records = json.loads((args.output / "runs.json").read_text(encoding="utf-8")) if args.resume else []
    seen = set()
    for row in records:
        identity = (row["round"], row["version"])
        assert identity not in seen and row["version"] in binaries and 1 <= row["round"] <= args.rounds
        seen.add(identity)
        data = json.loads((args.output / f"{row['round']}-{row['version']}.json").read_text(encoding="utf-8"))
        validate_report(data)
        row["module_counts"] = {m["type"]: {field: m[field] for field in ("requests", "candidates", "findings")}
                                for m in data["Modules"]}
    metadata = {"target": target, "rounds": args.rounds, "latency_ms": args.latency_ms,
                "instrumented": args.profile,
                "configuration": "CLI defaults; allow-private and JSON/silent output only",
                "binaries": {label: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                     "version": subprocess.check_output([str(path), "--version"], text=True, encoding="utf-8",
                                         env=dict(os.environ, XSSCAN_PERF_DIR=str((args.output / (label + "-version-profiles")).resolve())) if args.profile else None).strip()}
                             for label, path in binaries.items()}}
    if args.resume:
        previous = json.loads((args.output / "environment.json").read_text(encoding="utf-8"))
        for key in ("binaries", "latency_ms", "configuration", "rounds"):
            assert previous[key] == metadata[key], "resume configuration changed"
        assert previous.get("instrumented", False) == args.profile
    (args.output / ("resume-environment.json" if args.resume else "environment.json")).write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    try:
        for round_number in range(args.rounds):
            # Reverse alternate rounds to limit ordering and warm-cache bias.
            order = list(binaries.items())
            if round_number % 2:
                order.reverse()
            for label, binary in order:
                if any(r["round"] == round_number + 1 and r["version"] == label for r in records):
                    continue
                report = args.output / f"{round_number + 1}-{label}.json"
                if report.exists():
                    shutil.copyfile(report, report.with_suffix(".interrupted.json"))
                with lock:
                    requests.clear()
                start = time.perf_counter()
                environment = dict(os.environ)
                if args.profile:
                    environment["XSSCAN_PERF_DIR"] = str((args.output / f"{round_number + 1}-{label}-profiles").resolve())
                result = subprocess.run([str(binary), "--url", target, "--allow-private", "--silent",
                                         "--format", "json", "--output", str(report)],
                                        capture_output=True, timeout=240, env=environment)
                wall_ms = (time.perf_counter() - start) * 1000
                data = json.loads(report.read_text(encoding="utf-8"))
                modules, coverage = validate_report(data)
                assert result.returncode == 1 and not result.stdout and not result.stderr
                with lock:
                    received = list(requests)
                row = {"round": round_number + 1, "version": label, "wall_ms": wall_ms,
                       "duration_ms": data["Duration"], "module_ms": {k: v["duration_ms"] for k, v in modules.items()},
                       "requests_sent": data["RequestsSent"], "target_requests": len(received),
                       "payloads_sent": data["PayloadsSent"], "coverage": coverage,
                       "module_counts": {k: {field: v[field] for field in ("requests", "candidates", "findings")}
                                         for k, v in modules.items()},
                       "findings": [{k: f[k] for k in ("Type", "Parameter", "ExecutionVerified")} for f in data["Findings"]]}
                records.append(row)
                for previous in records[:-1]:
                    assert row["module_counts"] == previous["module_counts"], "module workload changed"
                    assert row["payloads_sent"] == previous["payloads_sent"], "payload workload changed"
                (args.output / "runs.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
                print(json.dumps(row), flush=True)
        summary = {}
        for row in records[1:]:
            assert row["module_counts"] == records[0]["module_counts"], "module workload changed"
            assert row["payloads_sent"] == records[0]["payloads_sent"], "payload workload changed"
        for label in binaries:
            rows = [r for r in records if r["version"] == label]
            assert len(rows) == args.rounds
            summary[label] = {"rounds": len(rows), "wall_median_ms": statistics.median(r["wall_ms"] for r in rows),
                              "modules_median_ms": {m: statistics.median(r["module_ms"][m] for r in rows)
                                                    for m in ("reflected", "dom", "stored")},
                              "target_requests": [r["target_requests"] for r in rows]}
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
