"""The cross-language digest corpus from ``prism-parity``.

This is the suite that could not be written inside one language. Every
per-language test of ``digest()`` passes trivially -- the implementation and the
expectation come from the same encoder -- and three implementations were
perfectly happy producing three different hashes for the same tool.

A digest is the material of a ``TrustPolicy`` pin. An operator computes one
against a running server and pastes it into a config, and nothing in either
language tells them the two disagree. It fails CLOSED, which is the safe
direction, but the failure looks like a rug pull that did not happen -- and the
usual response to a pin that refuses a tool you trust is to delete the pin.

Rows this language does not match the reference on are asserted as DIVERGENCES
rather than skipped. A skip removes the row from the report; this keeps it
visible and goes red the moment either side changes, which is what makes the
eventual fix detectable. See G-20.

Mirrors prism-mcp-ts/test/digest-corpus.test.ts case for case.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from prism_mcp import ToolDefinition

CORPUS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "mcp-tool-digest.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]
AGREEING = [case for case in CASES if case["agrees"]]
DIVERGING = [case for case in CASES if not case["agrees"]]


def _id(case: dict[str, Any]) -> str:
    return str(case["id"])


def test_the_corpus_is_whole_not_a_subset_someone_trimmed_to_green() -> None:
    assert len(CASES) == 10


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_produces_this_languages_recorded_digest(case: dict[str, Any]) -> None:
    assert ToolDefinition.from_payload(case["payload"]).digest() == case["digest"]["py"]


@pytest.mark.parametrize("case", AGREEING, ids=_id)
def test_agrees_with_the_php_reference_so_a_pin_transfers(case: dict[str, Any]) -> None:
    assert ToolDefinition.from_payload(case["payload"]).digest() == case["digest"]["php"]


@pytest.mark.parametrize("case", DIVERGING, ids=_id)
def test_still_diverges_from_the_reference(case: dict[str, Any]) -> None:
    # Asserted in the negative on purpose. When someone fixes G-20 this test
    # fails, which forces the corpus and the manifest's gap statement to be
    # updated in the same change rather than left claiming a divergence that no
    # longer exists.
    assert ToolDefinition.from_payload(case["payload"]).digest() != case["digest"]["php"]


def test_diverges_on_exactly_the_three_rows_the_manifest_names() -> None:
    assert [case["id"] for case in DIVERGING] == ["dig-0002", "dig-0003", "dig-0007"]


def test_agrees_with_typescript_on_every_row_including_the_divergent_ones() -> None:
    # The useful signal. Two ports disagreeing with the reference in the same
    # place is one reference-side artefact plus one coercion choice; two ports
    # disagreeing in DIFFERENT places would be two independent bugs, and a much
    # worse position.
    for case in CASES:
        assert case["digest"]["py"] == case["digest"]["ts"], case["id"]
