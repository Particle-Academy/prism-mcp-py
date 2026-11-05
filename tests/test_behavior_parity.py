import asyncio
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from prism_mcp import Client, McpDiagnostic, McpError, ResultGuard, ToolDefinition, TrustPolicy

PAYLOAD = {
    "name": "owned",
    "description": "Owned fixture",
    "inputSchema": {"type": "object", "properties": {}},
}
TOOL = ToolDefinition.from_payload(PAYLOAD)


def client_for(
    reply: Any,
    policy: TrustPolicy | None = None,
    on_diagnostic: Callable[[McpDiagnostic], None | Awaitable[None]] | None = None,
) -> tuple[Client, list[Any]]:
    calls: list[Any] = []

    async def transport(request: Any) -> Any:
        await asyncio.sleep(0)
        calls.append(request)
        return reply

    return Client(
        "configured",
        transport,
        policy or TrustPolicy.allowing_every_tool(),
        ResultGuard(frame_provenance=False),
        on_diagnostic=on_diagnostic,
    ), calls


@pytest.mark.parametrize("policy", [TrustPolicy.undeclared(), TrustPolicy.allowing([])])
def test_refuses_missing_or_empty_trust_before_transport(policy: TrustPolicy) -> None:
    client, calls = client_for({"tools": []}, policy)
    with pytest.raises(McpError) as caught:
        asyncio.run(client.list_tools())
    assert caught.value.code == "server_not_trusted"
    assert calls == []


def test_wildcard_empty_server_is_valid() -> None:
    client, calls = client_for({"tools": []})
    assert asyncio.run(client.list_tools()) == []
    assert len(calls) == 1


@pytest.mark.parametrize("value", [None, True, 0, 1, "", "false", "true", [], {}])
def test_present_non_false_is_error(value: Any) -> None:
    client, _ = client_for({"content": [{"type": "text", "text": "owned"}], "isError": value})
    assert asyncio.run(client.call_tool(TOOL)).is_error is True


@pytest.mark.parametrize("flags", [{}, {"isError": False}])
def test_absent_or_literal_false_is_success(flags: dict[str, Any]) -> None:
    client, _ = client_for({"content": [{"type": "text", "text": "owned"}], **flags})
    assert asyncio.run(client.call_tool(TOOL)).is_error is False


def test_default_cap_is_262144_utf8_bytes() -> None:
    guard = ResultGuard(frame_provenance=False)
    assert len(guard.guard("configured", "owned", "é" * 131072)) == 131072
    with pytest.raises(McpError) as caught:
        guard.guard("configured", "owned", "é" * 131073)
    assert caught.value.code == "result_too_large"


def test_error_cannot_bypass_the_cap() -> None:
    client, _ = client_for({"content": [{"type": "text", "text": "a" * 262145}], "isError": True})
    with pytest.raises(McpError) as caught:
        asyncio.run(client.call_tool(TOOL))
    assert caught.value.code == "result_too_large"


def test_omission_markers_keep_order_without_exposing_nontext_values() -> None:
    client, _ = client_for(
        {
            "content": [
                {"type": "text", "text": "alpha"},
                {"type": "image", "text": "SYNTHETIC_SECRET", "data": "SYNTHETIC_SECRET"},
                {"text": "SYNTHETIC_SECRET"},
                {"type": "text", "text": "omega"},
            ]
        }
    )
    assert (
        asyncio.run(client.call_tool(TOOL)).text
        == "alpha\n[image content omitted: this release passes text through only]\n[unknown content omitted: this release passes text through only]\nomega"
    )


def test_named_invalid_annotations_raise() -> None:
    bad = {
        **PAYLOAD,
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "object", "x-mcp-header": "Tenant"}},
        },
    }
    client, _ = client_for({"tools": [bad]}, TrustPolicy.allowing(["owned"]))
    with pytest.raises(McpError) as caught:
        asyncio.run(client.list_tools())
    assert caught.value.code == "mirrored_parameter_refused"


def test_missing_configured_names_warn_by_default() -> None:
    client, _ = client_for(
        {"tools": [PAYLOAD]}, TrustPolicy.allowing(["owned", "configured_missing"])
    )
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        assert [tool.name for tool in asyncio.run(client.list_tools())] == ["owned"]
    assert len(captured) == 1
    assert "configured_missing" in str(captured[0].message)


def test_configured_immutable_diagnostic_replaces_native_warning() -> None:
    events: list[McpDiagnostic] = []
    client, _ = client_for(
        {
            "tools": [
                PAYLOAD,
                {**PAYLOAD, "name": "REMOTE_SENTINEL", "description": "REMOTE_SECRET"},
            ]
        },
        TrustPolicy.allowing(["owned", "configured_missing"]),
        events.append,
    )
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        assert [tool.name for tool in asyncio.run(client.list_tools())] == ["owned"]
    assert events == [McpDiagnostic("configured", ("configured_missing",))]
    assert "REMOTE_" not in repr(events)
    assert captured == []
    with pytest.raises(FrozenInstanceError):
        events[0].server = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("kind", ["sync", "async", "cancelled"])
def test_diagnostic_failure_propagates_without_offering_tools(kind: str) -> None:
    failure = (
        asyncio.CancelledError("owned cancellation")
        if kind == "cancelled"
        else RuntimeError("owned diagnostic failure")
    )

    def failing(_event: McpDiagnostic) -> None:
        raise failure

    async def async_failing(_event: McpDiagnostic) -> None:
        await asyncio.sleep(0)
        raise failure

    client, _ = client_for(
        {"tools": []},
        TrustPolicy.allowing(["configured_missing"]),
        failing if kind == "sync" else async_failing,
    )
    with pytest.raises(type(failure)) as caught:
        asyncio.run(client.list_tools())
    assert caught.value is failure


def test_wildcard_has_no_missing_configured_name_diagnostic() -> None:
    events: list[McpDiagnostic] = []
    client, _ = client_for({"tools": [PAYLOAD]}, on_diagnostic=events.append)
    assert len(asyncio.run(client.list_tools())) == 1
    assert events == []


def test_diagnostic_cannot_silently_return_an_unawaited_inner_coroutine() -> None:
    async def inner() -> None:
        raise AssertionError("inner callback must not run")

    async def wrong(_event: McpDiagnostic) -> Any:
        return inner()

    client, _ = client_for({"tools": []}, TrustPolicy.allowing(["configured_missing"]), wrong)
    with pytest.raises(TypeError, match="inner coroutine"):
        asyncio.run(client.list_tools())


def test_wildcard_exclusions_are_detached_and_reset() -> None:
    replies = [
        {
            "tools": [
                {
                    **PAYLOAD,
                    "inputSchema": {
                        "properties": {"tenant": {"type": "object", "x-mcp-header": "Tenant"}}
                    },
                }
            ]
        },
        {"tools": [PAYLOAD]},
    ]

    async def send(_request: Any) -> Any:
        return replies.pop(0)

    client = Client("configured", send, TrustPolicy.allowing_every_tool())
    assert asyncio.run(client.list_tools()) == []
    excluded = client.excluded()
    assert "owned" in excluded
    excluded.clear()
    assert "owned" in client.excluded()
    assert len(asyncio.run(client.list_tools())) == 1
    assert client.excluded() == {}
