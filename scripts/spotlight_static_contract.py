#!/usr/bin/env python3
"""Permanent Selected Engineering Systems excluded from daily Spotlight rotation."""
from __future__ import annotations

STATIC_REPOSITORIES = frozenset(
    {
        "ai-qa-automation",
        "qa-automation-ai-agent-evals",
        "qa-automation-graphql",
        "qa-automation-visual-and-accessibility-playwright-axe",
    }
)
