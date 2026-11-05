# Prism MCP for Python

Consuming Model Context Protocol servers as Prism tools, across an explicit trust
boundary. The Python port of
[`particle-academy/prism-mcp`](https://github.com/Particle-Academy/prism-mcp).

Zero runtime dependencies. Python 3.10+.

```
pip install prism-ai-mcp
```

```python
from prism_mcp import Client, TrustPolicy

docs = Client(
    "docs",
    my_transport,
    trust=TrustPolicy.allowing(["search"], pins={"search": "sha256:3f1c…"}),
)


async def search_docs() -> None:
    tools = await docs.list_tools()
    result = await docs.call_tool(tools[0], {"query": "rate limits"})

    print(result.text)
```

`my_transport` is a callable that takes a `TransportRequest` (`method`, `params`,
`headers`) and returns an awaitable yielding the decoded server result. An
`async def` transport satisfies that contract. The package opens no connections
itself.

**Breaking change in 0.2.0:** `list_tools()` and `call_tool()` must be awaited,
and the transport must return an awaitable. Run `search_docs()` in your
application's event loop. A synchronous embedder must manage that loop itself;
the package provides one async client path.

**Security fix in 0.2.1:** in 0.2.0 an `async def` gate was never awaited. Its
coroutine is truthy, so a gate that returned `False` was read as consent and the
call was sent. If you wrote an async gate, upgrade.

## Trust

A tool list is not data the model summarises; it is instructions the model
follows. So nothing is offered until you say what you trust.

- **`TrustPolicy.undeclared()`** is the default. `list_tools()` raises
  `server_not_trusted` before sending a discovery request.
- **`TrustPolicy.allowing([...])`** offers only the named tools.
  `allowing([])` raises before discovery with a distinct empty allowlist message.
- **`TrustPolicy.allowing_every_tool()`** offers every tool, including ones the
  server adds later.
- **Pins.** Pass `pins={name: digest}`. `ToolDefinition.digest()` covers the
  tool's name, title, description and input schema, so a server that rewrites a
  description after you trusted it is refused with `tool_definition_changed`.

Wildcard trust also permits discovery of an empty server. Missing explicitly
configured tool names produce a native `McpDiagnosticWarning`. To handle the
diagnostic in your application, pass `on_diagnostic` to `Client`:

```python
async def report_missing(event: McpDiagnostic) -> None:
    # Frozen event: code, configured server and configured tool_names tuple.
    await report_missing_tools(event)


docs = Client(
    "docs", my_transport, trust=TrustPolicy.allowing(["search"]), on_diagnostic=report_missing
)
```

Import `McpDiagnostic` from `prism_mcp` for the type annotation. The callback
may be synchronous or async and replaces the native warning. It receives only
application-configured names, never arbitrary server strings. Callback failures
and cancellation propagate from `list_tools()` without returning tools. A
callback must await any inner coroutine before returning. Wildcard trust has
no configured tool names to report.

A `gate` callable `(server, tool, arguments) -> bool` is asked before every
call; returning `False` raises `tool_denied`. It may be sync or `async def`; an
async verdict is awaited before anything is sent. The default allows every call that
trust admitted, and `deny_all` refuses them all.

## Results

Every result passes through a `ResultGuard` before it reaches you:

- A result over `max_bytes` (262,144 UTF-8 bytes by default) raises
  `result_too_large` instead of being truncated. Set a smaller explicit bound
  when needed; `0` disables it.
- The text is wrapped in an `<untrusted-tool-output>` tag with a random id per
  result, so the server's output cannot close the wrapper.
- A `filter` callable `(server, tool, text) -> text` runs before framing, if you
  pass one. It must be synchronous; one that returns anything but `str` (an
  `async def` filter returns a coroutine) raises `TypeError`.

The wrapper makes a prompt injection harder. It does not make one impossible,
and the guard does not scan the text for injection strings.

Text parts are joined in order. Nontext or malformed object parts produce
explicit markers such as `[image content omitted: this release passes text
through only]`; their data and stray `text` fields are not forwarded. Missing
or nonstring type labels are labelled `unknown`. The same bounds, filter and frame apply to errors.

Only an absent `isError` or literal `False` reports success. Every other present
value, including `None`, `0`, an empty string or a container, sets
`result.is_error` to `True`. Tool failure remains a guarded result; transport
failures raise separately.

## Mirrored parameters

A tool's schema can mark an argument with `x-mcp-header`, which copies the
model's value into an `Mcp-Param-*` request header. A tool whose annotations
break the rules (an invalid header name, two arguments mirrored to the same
header) raises `mirrored_parameter_refused` if your allowlist names it explicitly.
With wildcard trust it is excluded. `client.excluded()` returns a detached
dictionary of excluded names and reasons, reset on each discovery. Treat those
reasons as untrusted server data. Mirrored header value encoding is unchanged.

## Protocol

The client speaks MCP `2026-07-28`, the stateless revision. Earlier revisions
open with an `initialize` handshake and a session, which this client does not
implement. `is_stateless_protocol(version)` tells the two apart.

## Errors

Every failure is an `McpError` with a stable `code`: `server_not_trusted`,
`tool_definition_changed`, `tool_denied`, `result_too_large`,
`mirrored_parameter_refused`, `unsupported_protocol_version`,
`protocol_failure`, `tool_call_failed`, `server_not_configured`.

## Parity

prism-parity's `mcp-tool-digest` corpus pins tool digests against the PHP
reference and the TypeScript port, so a pin computed in one language holds in
the others.

One case is not in that corpus: a schema containing an integral float such as
`1.0` digests differently here than in PHP and TypeScript. For such a tool,
compute the pin in Python.

## License

MIT. See [LICENSE](LICENSE).
