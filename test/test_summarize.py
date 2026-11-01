"""Regression checks for the CI result gate, using synthetic event records."""

import json
import tempfile
import unittest
from pathlib import Path

from summarize import summarize


class SummaryTests(unittest.TestCase):
    def check_records(self, events, repeats=1):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
            return summarize(path, repeats)

    def corpus(self):
        events = []
        for module in ("reflected", "dom", "stored", "blind"):
            for safe in (False, True):
                record = dict(module=module, safe=safe, outcome="TN" if safe else "TP",
                              target_requests=1, callback_requests=0, wall_ms=1,
                              go_total_alloc_bytes=1, go_heap_inuse_after_bytes=1)
                events.append({"Output": "BASELINE " + json.dumps(record)})
        events.append({"Action": "pass", "Package": "fixture"})
        return events

    def test_complete_corpus(self):
        result = self.check_records(self.corpus())
        self.assertEqual(result["fixture_outcomes"], {"TP": 4, "TN": 4})

    def test_missing_case(self):
        with self.assertRaises(ValueError):
            self.check_records(self.corpus()[1:])

    def test_duplicate_case(self):
        events = self.corpus()
        with self.assertRaises(ValueError):
            self.check_records(events + [events[0]])

    def test_package_failure(self):
        events = self.corpus()
        events[-1]["Action"] = "fail"
        with self.assertRaises(ValueError):
            self.check_records(events)

    def test_false_positive(self):
        events = self.corpus()
        record = json.loads(events[1]["Output"].split("BASELINE ")[1])
        record["outcome"] = "FP"
        events[1]["Output"] = "BASELINE " + json.dumps(record)
        with self.assertRaises(ValueError):
            self.check_records(events)

    def test_no_results(self):
        with self.assertRaises(ValueError):
            self.check_records([], repeats=0)

    def test_failure_cannot_be_overwritten(self):
        events = [{"Action": "fail", "Package": "same"},
                  {"Action": "pass", "Package": "same"}]
        with self.assertRaises(ValueError):
            self.check_records(events, repeats=0)

    def test_missing_terminal_result(self):
        events = [{"Action": "start", "Package": "missing"},
                  {"Action": "pass", "Package": "healthy"}]
        with self.assertRaises(ValueError):
            self.check_records(events, repeats=0)

    def test_required_scope_cannot_be_replaced_by_extra_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events, required = root / "events.json", root / "required.txt"
            events.write_text(json.dumps({"Action": "pass", "Package": "fixture", "Test": "Extra"}) + "\n" +
                              json.dumps({"Action": "pass", "Package": "fixture"}), encoding="utf-8")
            required.write_text("fixture\tOriginal\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                summarize(events, required_tests=required)

    def test_required_scope_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events, required = root / "events.json", root / "required.txt"
            events.write_text(json.dumps({"Action": "pass", "Package": "fixture", "Test": "Original"}) + "\n" +
                              json.dumps({"Action": "pass", "Package": "fixture"}), encoding="utf-8")
            required.write_text("# original scope\nfixture\tOriginal\n", encoding="utf-8")
            self.assertEqual(summarize(events, required_tests=required)["required_tests"], {"total": 1, "passed": 1})


if __name__ == "__main__":
    unittest.main()
