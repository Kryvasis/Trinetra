import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "tools" / "measure_accuracy.py"
SPEC = importlib.util.spec_from_file_location("measure_accuracy", MODULE_PATH)
measure_accuracy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure_accuracy)


def record(index, vendor="Cisco IOS XE", expected="pass", actual="pass"):
    return {
        "case_id": f"case-{index}", "vendor": vendor, "os_version": "test",
        "control_id": "V-006", "expected": expected, "actual": actual,
        "reviewer": "independent-reviewer", "source_reference": "lab-ticket-1",
    }


def test_accuracy_measurement_is_reproducible_and_scoped():
    records = [record(i, "Cisco IOS XE" if i < 10 else "Juniper JunOS") for i in range(20)]
    records[0]["expected"] = "fail"
    records[0]["actual"] = "fail"
    records[1]["actual"] = "fail"
    result = measure_accuracy.measure(records, "a" * 64)
    assert result["observations"] == 20
    assert result["corpus_sha256"] == "a" * 64
    assert result["fail_detection"]["precision"] == 0.5
    assert result["fail_detection"]["recall"] == 1.0


def test_accuracy_measurement_refuses_misleading_scope():
    with pytest.raises(ValueError, match="20"):
        measure_accuracy.measure([record(1)], "b" * 64)
    with pytest.raises(ValueError, match="two vendors"):
        measure_accuracy.measure([record(i) for i in range(20)], "b" * 64)
