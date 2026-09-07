#!/usr/bin/env python3
"""Fail closed on floating or misresolved Python runtimes in authored workflows."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
EXPECTED_VERSION = "3.13.15"
EXPECTED_VERSION_INFO = tuple(int(part) for part in EXPECTED_VERSION.split("."))
EXPECTED_WORKFLOWS = {
    "profile-quality.yml",
    "profile-stats.yml",
    "spotlight-link-sync.yml",
}
SETUP_PYTHON = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*actions/setup-python@[0-9a-f]{40}\s+#\s+v[0-9]+\.[0-9]+\.[0-9]+\s*$")
VERSION_LINE = f'  PYTHON_VERSION: "{EXPECTED_VERSION}"'
VERSION_INPUT = "          python-version: ${{ env.PYTHON_VERSION }}"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validate_running_interpreter() -> str:
    observed = tuple(sys.version_info[:3])
    require(sys.implementation.name == "cpython",
            f"runtime implementation drifted: observed={sys.implementation.name} expected=cpython")
    require(observed == EXPECTED_VERSION_INFO,
            f"runtime version drifted: observed={'.'.join(map(str, observed))} expected={EXPECTED_VERSION}")
    return ".".join(map(str, observed))


def workflow_files() -> list[Path]:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    return sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})


def validate_text(text: str, label: str) -> bool:
    setup_count = len(SETUP_PYTHON.findall(text))
    if setup_count == 0:
        require("PYTHON_VERSION:" not in text,
                f"{label}: declares PYTHON_VERSION without an authored setup-python execution surface")
        return False

    require(text.count(VERSION_LINE) == 1,
            f"{label}: Python runtime must be pinned exactly once to {EXPECTED_VERSION}")
    require(text.count("PYTHON_VERSION:") == 1,
            f"{label}: Python runtime declaration must have one canonical source")
    require(text.count(VERSION_INPUT) == setup_count,
            f"{label}: every setup-python step must consume the canonical PYTHON_VERSION")

    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("python-version:"):
            require(stripped == "python-version: ${{ env.PYTHON_VERSION }}",
                    f"{label}: setup-python may not use an inline or floating runtime: {stripped}")
    return True


def validate_repository() -> None:
    observed: set[str] = set()
    for path in workflow_files():
        text = path.read_text(encoding="utf-8")
        if validate_text(text, path.name):
            observed.add(path.name)
    require(observed == EXPECTED_WORKFLOWS,
            "Python-bearing workflow inventory changed: "
            f"observed={sorted(observed)} expected={sorted(EXPECTED_WORKFLOWS)}")

    quality = QUALITY.read_text(encoding="utf-8")
    require("python3 scripts/validate-python-runtime-contract.py" in quality,
            "Profile Quality must execute the Python runtime reproducibility contract")


def expect_failure(text: str, expected: str) -> None:
    try:
        validate_text(text, "self-test.yml")
    except ValueError as exc:
        require(expected in str(exc), f"self-test failed for the wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden Python runtime drift: {expected}")


def self_test() -> None:
    setup = "      - uses: actions/setup-python@" + ("a" * 40) + " # v7.0.0\n"
    good = (
        "env:\n"
        f"  PYTHON_VERSION: \"{EXPECTED_VERSION}\"\n"
        "steps:\n"
        + setup
        + "        with:\n"
        + "          python-version: ${{ env.PYTHON_VERSION }}\n"
    )
    require(validate_text(good, "self-test-good.yml"), "self-test rejected exact Python runtime pin")
    expect_failure(good.replace(EXPECTED_VERSION, "3.13", 1), "pinned exactly once")
    expect_failure(
        good.replace("python-version: ${{ env.PYTHON_VERSION }}", f"python-version: {EXPECTED_VERSION}", 1),
        "canonical PYTHON_VERSION",
    )


def main() -> int:
    try:
        observed_version = validate_running_interpreter()
        self_test()
        validate_repository()
        print(
            "Python runtime contract passed: authored setup-python execution is closed to "
            f"{EXPECTED_VERSION} across exactly {len(EXPECTED_WORKFLOWS)} reviewed workflows; "
            f"observed interpreter=CPython {observed_version}."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
