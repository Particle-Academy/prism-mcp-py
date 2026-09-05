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

**All thirteen rows agree as of 2026-09-04.** Three did not: dig-0002 and
dig-0003 were closed in the REFERENCE, which stopped rendering an empty
map-typed field as ``[]``, and dig-0007 was closed HERE, by coercing an absent
description to ``""`` as the reference always has. Opposite directions, each
judged on its own merits. G-20.

Every digest in the corpus changed as a result. A pin recorded before that date
matches none of the three implementations and has to be recomputed.

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
BY_ID: dict[str, dict[str, Any]] = {str(case["id"]): case for case in CASES}


def _id(case: dict[str, Any]) -> str:
    return str(case["id"])


def _payload(case_id: str) -> dict[str, Any]:
    payload: dict[str, Any] = BY_ID[case_id]["payload"]

    return payload


def test_the_corpus_is_whole_not_a_subset_someone_trimmed_to_green() -> None:
    assert len(CASES) == 13


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_produces_this_languages_recorded_digest(case: dict[str, Any]) -> None:
    assert ToolDefinition.from_payload(case["payload"]).digest() == case["digest"]["py"]


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_agrees_with_the_php_reference_so_a_pin_transfers(case: dict[str, Any]) -> None:
    assert ToolDefinition.from_payload(case["payload"]).digest() == case["digest"]["php"]


def test_records_no_divergence_because_there_is_none_left_to_record() -> None:
    # The three rows that used to be asserted in the NEGATIVE are gone, which is
    # what closing G-20 looks like from here. Kept as a positive assertion rather
    # than deleted: a suite that simply stopped mentioning divergence could not
    # tell "fixed" from "no longer checked".
    assert [case["id"] for case in CASES if not case["agrees"]] == []


def test_agrees_with_typescript_on_every_row() -> None:
    # Two ports disagreeing with the reference in the same place was the useful
    # signal while G-20 was open -- one reference-side artefact plus one coercion
    # choice, rather than two independent port bugs. Kept now because it is the
    # cheapest way to notice one port being fixed without the other.
    for case in CASES:
        assert case["digest"]["py"] == case["digest"]["ts"], case["id"]


def test_an_absent_schema_and_an_explicitly_empty_one_are_the_same_tool() -> None:
    # dig-0002 omits `inputSchema`; dig-0011 sends `{}`. A server that starts
    # emitting a field it used to leave out has not rewritten its tool, and a pin
    # that broke on that would be deleted by the first operator it hit.
    assert (
        ToolDefinition.from_payload(_payload("dig-0002")).digest()
        == ToolDefinition.from_payload(_payload("dig-0011")).digest()
    )


def test_an_empty_list_digests_as_a_list_so_the_reference_fix_did_not_over_reach() -> None:
    # The guard on the FIX rather than on the defect. `required` is a list and
    # `properties` is a map; a rule that promoted every empty array to an object
    # would have rendered `"required": []` as `{}` -- green on the rows the fix
    # was for, and broken on a far more ordinary one. This language never had the
    # ambiguity, so this row is what makes it the reference's check too.
    as_list = ToolDefinition.from_payload(_payload("dig-0012"))
    as_map = ToolDefinition.from_payload(
        {
            "name": "search",
            "description": "d",
            "inputSchema": {"type": "object", "properties": {}, "required": {}},
        }
    )

    assert as_list.digest() != as_map.digest()
    assert as_list.digest() == BY_ID["dig-0012"]["digest"]["php"]
