#!/usr/bin/env python3
"""Fail closed on floating or misresolved Python runtimes in authored workflows."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
RUNTIME_PROBE = ROOT / "scripts/verify-python-runtime.py"
FRESHNESS_CHECKER = ROOT / "scripts/check-python-maintenance-freshness.py"
EXPECTED_VERSION = "3.13.15"
EXPECTED_VERSION_INFO = tuple(int(part) for part in EXPECTED_VERSION.split("."))
EXPECTED_WORKFLOWS = {
    "profile-quality.yml",
    "profile-stats.yml",
    "spotlight-link-sync.yml",
}
VERIFY_COMMANDS = {
    "profile-quality.yml": "python3 scripts/verify-python-runtime.py",
    "profile-stats.yml": "python3 source/scripts/verify-python-runtime.py",
    "spotlight-link-sync.yml": "python3 source/scripts/verify-python-runtime.py",
}
VERIFY_STEP_NAME = "      - name: Verify resolved Python runtime"
QUALITY_IDENTITY_STEP_NAME = "      - name: Validate privileged workflow byte identity"
QUALITY_IDENTITY_COMMAND = "python3 scripts/validate-privileged-workflow-identity.py"
SETUP_PYTHON = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*actions/setup-python@[0-9a-f]{40}\s+#\s+v[0-9]+\.[0-9]+\.[0-9]+\s*$")
VERSION_LINE = f'  PYTHON_VERSION: "{EXPECTED_VERSION}"'
VERSION_INPUT = "          python-version: ${{ env.PYTHON_VERSION }}"
FRESHNESS_SEQUENCE = (
    "      - name: Validate exact Python runtime contract\n"
    "        run: python3 scripts/validate-python-runtime-contract.py\n\n"
    "      - name: Check Python maintenance freshness\n"
    "        run: python3 scripts/check-python-maintenance-freshness.py"
)


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def runtime_probe_pair(command: str) -> re.Pattern[str]:
    return re.compile(
        r"(?m)^      - name: Set up Python\n"
        r"        uses: actions/setup-python@[0-9a-f]{40}\s+#\s+v[0-9]+\.[0-9]+\.[0-9]+\s*\n"
        r"        with:\n"
        r"          python-version: \$\{\{ env\.PYTHON_VERSION \}\}\n\n"
        r"      - name: Verify resolved Python runtime\n"
        rf"        run: {re.escape(command)}$"
    )


def quality_identity_probe_pair(command: str) -> re.Pattern[str]:
    return re.compile(
        r"(?m)^      - name: Set up Python\n"
        r"        uses: actions/setup-python@[0-9a-f]{40}\s+#\s+v[0-9]+\.[0-9]+\.[0-9]+\s*\n"
        r"        with:\n"
        r"          python-version: \$\{\{ env\.PYTHON_VERSION \}\}\n\n"
        r"      - name: Validate privileged workflow byte identity\n"
        rf"        run: {re.escape(QUALITY_IDENTITY_COMMAND)}\n\n"
        r"      - name: Verify resolved Python runtime\n"
        rf"        run: {re.escape(command)}$"
    )


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
    require(RUNTIME_PROBE.is_file(), "exact Python runtime probe is missing")
    require(FRESHNESS_CHECKER.is_file(), "Python maintenance freshness checker is missing")
    observed: set[str] = set()
    for path in workflow_files():
        text = path.read_text(encoding="utf-8")
        if validate_text(text, path.name):
            observed.add(path.name)
            setup_count = len(SETUP_PYTHON.findall(text))
            require(path.name in VERIFY_COMMANDS,
                    f"{path.name}: Python-bearing workflow lacks a reviewed runtime probe command")
            command = VERIFY_COMMANDS[path.name]
            require(text.count(VERIFY_STEP_NAME) == setup_count,
                    f"{path.name}: every setup-python execution must be followed by one named runtime probe")
            require(text.count(f"        run: {command}") == setup_count,
                    f"{path.name}: every setup-python execution must invoke the reviewed runtime probe")
            direct_pair_count = len(runtime_probe_pair(command).findall(text))
            if path.name == "profile-quality.yml":
                require(text.count(QUALITY_IDENTITY_STEP_NAME) == 1,
                        "profile-quality.yml: exact workflow identity gate must appear once")
                require(text.count(f"        run: {QUALITY_IDENTITY_COMMAND}") == 1,
                        "profile-quality.yml: exact workflow identity gate command changed")
                gated_pair_count = len(quality_identity_probe_pair(command).findall(text))
                require(gated_pair_count == 1,
                        "profile-quality.yml: exactly one setup-python step must be followed immediately by the "
                        "reviewed workflow identity gate and then the runtime probe")
                require(direct_pair_count + gated_pair_count == setup_count,
                        "profile-quality.yml: every setup-python step must reach the runtime probe either directly "
                        "or through the single exact workflow identity gate: "
                        f"direct={direct_pair_count} gated={gated_pair_count} setup={setup_count}")
            else:
                require(direct_pair_count == setup_count,
                        f"{path.name}: runtime probe must immediately follow every setup-python step: "
                        f"paired={direct_pair_count} setup={setup_count}")
    require(observed == EXPECTED_WORKFLOWS,
            "Python-bearing workflow inventory changed: "
            f"observed={sorted(observed)} expected={sorted(EXPECTED_WORKFLOWS)}")

    quality = QUALITY.read_text(encoding="utf-8")
    require("python3 scripts/validate-python-runtime-contract.py" in quality,
            "Profile Quality must execute the Python runtime reproducibility contract")
    require(quality.count(FRESHNESS_SEQUENCE) == 1,
            "Profile Quality must run the reviewed maintenance freshness checker immediately after the exact runtime contract")


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

    command = "python3 scripts/verify-python-runtime.py"
    setup_block = (
        "      - name: Set up Python\n"
        + "        uses: actions/setup-python@" + ("a" * 40) + " # v7.0.0\n"
        + "        with:\n"
        + "          python-version: ${{ env.PYTHON_VERSION }}\n\n"
    )
    exact_pair = (
        setup_block
        + "      - name: Verify resolved Python runtime\n"
        + f"        run: {command}\n"
    )
    require(len(runtime_probe_pair(command).findall(exact_pair)) == 1,
            "self-test rejected immediate runtime probe ordering")
    exact_gated_pair = (
        setup_block
        + "      - name: Validate privileged workflow byte identity\n"
        + f"        run: {QUALITY_IDENTITY_COMMAND}\n\n"
        + "      - name: Verify resolved Python runtime\n"
        + f"        run: {command}\n"
    )
    require(len(quality_identity_probe_pair(command).findall(exact_gated_pair)) == 1,
            "self-test rejected the single reviewed identity gate before runtime proof")
    altered_gate = exact_gated_pair.replace(QUALITY_IDENTITY_COMMAND, "python3 scripts/other.py", 1)
    require(len(quality_identity_probe_pair(command).findall(altered_gate)) == 0,
            "self-test accepted an altered identity gate before runtime proof")
    intervening = exact_pair.replace(
        "\n      - name: Verify resolved Python runtime\n",
        "\n      - name: Intervening action\n"
        "        run: echo forbidden-before-runtime-proof\n\n"
        "      - name: Verify resolved Python runtime\n",
    )
    require(len(runtime_probe_pair(command).findall(intervening)) == 0,
            "self-test accepted an arbitrary intervening step before the runtime probe")
    require(len(quality_identity_probe_pair(command).findall(intervening)) == 0,
            "self-test confused an arbitrary intervening step with the reviewed identity gate")


def main() -> int:
    try:
        observed_version = validate_running_interpreter()
        self_test()
        validate_repository()
        print(
            "Python runtime contract passed: authored setup-python execution is closed to "
            f"{EXPECTED_VERSION} across exactly {len(EXPECTED_WORKFLOWS)} reviewed workflows; "
            "all setup jobs execute the reviewed runtime probe immediately after setup except the single "
            "Profile Quality path that first executes the exact governed-workflow byte gate; "
            "Profile Quality also owns the maintenance-line freshness gate; "
            f"observed interpreter=CPython {observed_version}."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
