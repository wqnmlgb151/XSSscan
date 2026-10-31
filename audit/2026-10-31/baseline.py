"""Local-only CLI baseline; Python standard library, no scanner modifications.

Usage: python baseline.py --exe /absolute/path/xsscan.exe --out /path/results
Raw reports contain deliberately synthetic credentials. Never use real tokens.
"""

import argparse
import hashlib
import html
import json
import os
import platform
import signal
import statistics
import subprocess
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("repeats must be positive")
    exe, out = args.exe.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    state = {"mode": "safe", "delay": 0, "counts": Counter()}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                mode, delay = state["mode"], state["delay"]
                # Go requests can use browser-like UAs; never classify by UA.
                kind = "with_sec_fetch" if self.headers.get("Sec-Fetch-Mode") else "without_sec_fetch"
                state["counts"][kind] += 1
                state["counts"]["total"] += 1
            u = urlsplit(self.path)
            if u.path == "/asset":
                self.send_response(204)
                self.end_headers()
                return
            time.sleep(delay)
            values = parse_qs(u.query)
            q = values.get("q", [""])[0]
            if mode == "safe":
                q = html.escape(q)
            if mode == "independent":
                q = "<div>" + values.get("a", [""])[0] + "</div><p>" + values.get("b", [""])[0] + "</p>"
            if mode == "ambiguous":
                q = "<div>" + q + "</div><p>" + q + "</p>"
            fanout = ""
            if mode == "fanout":
                fanout = "<script>for(let i=0;i<24;i++)fetch('/asset?i='+i)</script>"
            body = ("<html><body>" + q + fanout + "</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "audit_response=AUDIT_RESPONSE_SYNTHETIC; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    # Bind above Chrome's restricted low ports; never weaken browser policy.
    server = None
    for port in range(24000, 24100):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if server is None:
        raise RuntimeError("no free loopback fixture port in 24000..24099")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    rows = []

    def run(mode, strategy, delay=0, fmt="json", budget=100, verify=True):
        with lock:
            state.update(mode=mode, delay=delay, counts=Counter())
        name = f"{len(rows):03d}-{mode}-{strategy}-{fmt}"
        report = out / (name + "." + fmt)
        query = "a=test&b=test" if mode == "independent" else "q=test"
        command = [str(exe), "--url", f"http://127.0.0.1:{server.server_port}/?{query}",
                   "--types", "reflected", "--allow-private", "--silent",
                   "--max-payloads", "4", "--workers", "4", "--strategy", strategy,
                   "--request-budget", str(budget), "--module-timeout", "40",
                   "--timeout", "5", "--verify-timeout", "5", "--format", fmt,
                   "--output", str(report), "--header", "Authorization: Bearer AUDIT_AUTH_SYNTHETIC",
                   "--cookie", "audit_session=AUDIT_COOKIE_SYNTHETIC"]
        if not verify:
            command.append("--verify-execution=false")
        start = time.perf_counter()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=os.name != "nt")
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            rows.append(dict(name=name, timeout=True, pid=process.pid))
            (out / "raw-results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, timeout=10, check=False)
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
            raise RuntimeError(f"fixture timeout (see failed row): {name}") from None
        elapsed = time.perf_counter() - start
        # Account for requests already being serviced as the browser closes.
        time.sleep(0.1)
        with lock:
            counts = dict(state["counts"])
        text = report.read_text(encoding="utf-8") if report.exists() else ""
        data = json.loads(text) if fmt == "json" and text else {}
        row = dict(name=name, mode=mode, strategy=strategy, delay_ms=delay * 1000,
                   format=fmt, budget=budget, verify=verify, wall_s=elapsed,
                   exit=process.returncode, server=counts, status=data.get("Status"),
                   requests=data.get("RequestsSent"), payloads=data.get("PayloadsSent"),
                   findings=len(data.get("Findings") or []) if data else None,
                   verified=sum(bool(f.get("ExecutionVerified")) for f in data.get("Findings") or []) if data else None,
                   coverage=data.get("Coverage", data.get("coverage", [])),
                   verified_parameters=sorted({f.get("Parameter") for f in data.get("Findings") or []
                                               if f.get("ExecutionVerified")}),
                   synthetic_credentials={token: token in text for token in
                       ["AUDIT_AUTH_SYNTHETIC", "AUDIT_COOKIE_SYNTHETIC", "AUDIT_RESPONSE_SYNTHETIC"]},
                   stdout_bytes=len(stdout), stderr_bytes=len(stderr))
        rows.append(row)
        (out / "raw-results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(json.dumps(row), flush=True)
        if process.returncode not in (0, 1, 2):
            raise RuntimeError(f"scanner terminated abnormally: {name}")
        if not text or stdout or stderr:
            raise RuntimeError(f"missing report or silent-output violation: {name}")
        expected_exit = 0 if mode == "safe" else 2
        if process.returncode != expected_exit:
            raise RuntimeError(f"unexpected fixture verdict: {name}")
        if fmt == "json":
            if row["status"] != "completed":
                raise RuntimeError(f"fixture scan incomplete: {name}")
            if verify and mode != "safe" and not row["verified"]:
                raise RuntimeError(f"fixture execution proof missing: {name}")
            if mode == "independent" and row["verified_parameters"] != ["a", "b"]:
                raise RuntimeError(f"independent input suppressed: {name}")
            if mode != "safe" and not any(c["stage"] == "reflected_candidates" for c in row["coverage"]):
                raise RuntimeError(f"candidate coverage missing: {name}")
            for coverage in row["coverage"]:
                if coverage["stage"] == "reflected_candidates" and (mode == "ambiguous" or strategy == "exhaustive"):
                    if coverage["started"] != coverage["planned"] or coverage["not_started"] != 0:
                        raise RuntimeError(f"full candidate range suppressed: {name}")
                if coverage["started"] != sum(coverage[k] for k in ["completed", "failed", "canceled"]):
                    raise RuntimeError(f"coverage accounting mismatch: {name}")
                if coverage["planned_known"] and coverage["planned"] != coverage["started"] + coverage["not_started"]:
                    raise RuntimeError(f"planned coverage mismatch: {name}")

    try:
        for repeat in range(args.repeats):
            # Alternate order to reduce warm-cache/order bias; no warm-up excluded.
            strategies = ["adaptive", "exhaustive"] if repeat % 2 == 0 else ["exhaustive", "adaptive"]
            for mode, delay in [("safe", 0), ("vulnerable", 0), ("vulnerable", 0.05),
                                ("ambiguous", 0), ("independent", 0)]:
                for strategy in strategies:
                    run(mode, strategy, delay)
        run("fanout", "adaptive", budget=8)
        for fmt in ["json", "markdown", "html", "sarif", "junit"]:
            run("vulnerable", "exhaustive", fmt=fmt, verify=False)
        groups = {}
        for row in rows[:args.repeats * 10]:
            key = f"{row['mode']}/{row['delay_ms']}/{row['strategy']}"
            groups.setdefault(key, []).append(row)
        summary = {key: dict(samples=len(group),
                     wall_median_s=statistics.median(r["wall_s"] for r in group),
                     wall_min_s=min(r["wall_s"] for r in group),
                     wall_max_s=max(r["wall_s"] for r in group),
                     requests=[r["requests"] for r in group],
                     payloads=[r["payloads"] for r in group],
                     verified=[r["verified"] for r in group],
                     statuses=[r["status"] for r in group]) for key, group in groups.items()}
        metadata = dict(platform=platform.platform(), python=platform.python_version(),
                        exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                        version=subprocess.check_output([str(exe), "--version"], text=True).strip(),
                        fixture_origin=f"http://127.0.0.1:{server.server_port}",
                        repeats=args.repeats, summary=summary)
        (out / "summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
