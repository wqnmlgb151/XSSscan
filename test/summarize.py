"""Summarize Go test JSON and validate the eight-case synthetic baseline."""

import argparse
import collections
import json
import statistics
from pathlib import Path


def summarize(path, repeats=0):
    counts = collections.Counter()
    packages = {}
    active = set()
    failed_packages = set()
    records = []
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        event = json.loads(line)
        action = event.get("Action")
        package = event.get("Package")
        identity = (package, event.get("Test"))
        if action in ("start", "run"):
            active.add(identity)
        if action in ("pass", "fail", "skip"):
            active.discard(identity)
        if event.get("Test") and action in ("pass", "fail", "skip"):
            counts[action] += 1
        if not event.get("Test") and action in ("pass", "fail", "skip"):
            packages[event["Package"]] = action
            if action == "fail":
                failed_packages.add(package)
        output = event.get("Output", "")
        if "BASELINE {" in output:
            records.append(json.loads(output.split("BASELINE ", 1)[1]))
    if not packages or active or failed_packages or counts["fail"]:
        raise ValueError("missing terminal results or failed tests")
    result = {"test_events": dict(counts), "packages": packages}
    if repeats:
        expected = {(module, safe) for module in ("reflected", "dom", "stored", "blind") for safe in (False, True)}
        grouped = collections.defaultdict(list)
        for record in records:
            grouped[record["module"], record["safe"]].append(record)
            if record.get("error") or record["outcome"] != ("TN" if record["safe"] else "TP") or record["target_requests"] <= 0:
                raise ValueError("failed or unexercised labeled fixture")
        if set(grouped) != expected or any(len(rows) != repeats for rows in grouped.values()):
            raise ValueError("missing or duplicate baseline cases")
        metrics = ("target_requests", "callback_requests", "wall_ms", "go_total_alloc_bytes", "go_heap_inuse_after_bytes")
        result["baseline"] = [
            {"module": module, "safe": safe, "runs": len(rows),
             **{metric: {"median": statistics.median(row[metric] for row in rows),
                         "min": min(row[metric] for row in rows),
                         "max": max(row[metric] for row in rows)} for metric in metrics}}
            for (module, safe), rows in sorted(grouped.items())
        ]
        result["fixture_outcomes"] = dict(collections.Counter(row["outcome"] for row in records))
        result["scope"] = "Synthetic candidate verdicts only; Go heap samples exclude Chrome and are not peak RSS."
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("--baseline-repeats", type=int, default=0)
    args = parser.parse_args()
    if args.baseline_repeats < 0:
        parser.error("--baseline-repeats must be nonnegative")
    print(json.dumps(summarize(args.input, args.baseline_repeats), indent=2))
