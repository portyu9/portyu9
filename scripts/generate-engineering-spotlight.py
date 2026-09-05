#!/usr/bin/env python3
"""Compatibility entrypoint for ledger-backed Engineering Evidence Spotlight v2.1."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

MODULE = Path(__file__).with_name("generate-engineering-spotlight-from-ledger.py")
spec = spec_from_file_location("generate_engineering_spotlight_from_ledger", MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load ledger-backed Engineering Spotlight generator")
module = module_from_spec(spec)
spec.loader.exec_module(module)
main = module.main

if __name__ == "__main__":
    raise SystemExit(main())
