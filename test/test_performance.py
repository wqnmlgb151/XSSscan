"""The performance harness must reject incomplete or reduced detection work."""

import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("performance_ab", Path(__file__).parent / "performance/ab.py")
ab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ab)


class PerformanceValidationTests(unittest.TestCase):
    def fixture(self):
        return {"Modules": [{"type": kind, "status": "skipped" if kind == "blind" else "completed",
                             "requests": 20 if kind == "stored" else 0, "candidates": 3 if kind == "stored" else 0}
                            for kind in ("reflected", "dom", "stored", "blind")],
                "coverage": [{"stage": "dom_source_checks", "planned": 65, "started": 65, "completed": 65,
                              "failed": 0, "canceled": 0, "not_started": 0}],
                "RequestsSent": 24, "PayloadsSent": 9,
                "Findings": [{"ExecutionVerified": True, "Parameter": "id"}]}

    def test_complete_workload(self):
        ab.validate_report(self.fixture())

    def test_reduced_or_incomplete_workload_is_rejected(self):
        original = self.fixture()
        corruptions = [lambda d: d["Modules"][2].update(status="canceled"),
                       lambda d: d["Modules"][2].update(requests=5),
                       lambda d: d["Modules"][2].update(candidates=1),
                       lambda d: d["coverage"][0].update(completed=64),
                       lambda d: d["coverage"][0].update(failed=1),
                       lambda d: d.update(PayloadsSent=8),
                       lambda d: d["Findings"][0].update(ExecutionVerified=False)]
        for number, corrupt in enumerate(corruptions):
            with self.subTest(case=number):
                data = copy.deepcopy(original)
                corrupt(data)
                with self.assertRaises(AssertionError):
                    ab.validate_report(data)


if __name__ == "__main__":
    unittest.main()
