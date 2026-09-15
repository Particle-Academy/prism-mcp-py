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

tools = docs.list_tools()
result = docs.call_tool(tools[0], {"query": "rate limits"})

print(result.text)
```

`my_transport` is a callable that sends a `TransportRequest` (`method`, `params`,
`headers`) to the server and returns the decoded result. The package opens no
connections itself.

## Trust

A tool list is not data the model summarises; it is instructions the model
follows. So nothing is offered until you say what you trust.

- **`TrustPolicy.undeclared()`** is the default. `list_tools()` raises
  `server_not_trusted` instead of returning the server's tools.
- **`TrustPolicy.allowing([...])`** offers only the named tools.
  `allowing([])` is a declaration too, and offers nothing.
- **`TrustPolicy.allowing_every_tool()`** offers every tool, including ones the
  server adds later.
- **Pins.** Pass `pins={name: digest}`. `ToolDefinition.digest()` covers the
  tool's name, title, description and input schema, so a server that rewrites a
  description after you trusted it is refused with `tool_definition_changed`.

A `gate` callable `(server, tool, arguments) -> bool` is asked before every
call; returning `False` raises `tool_denied`. The default allows every call that
trust admitted, and `deny_all` refuses them all.

## Results

Every result passes through a `ResultGuard` before it reaches you:

- A result over `max_bytes` (65,536 by default) raises `result_too_large`
  instead of being truncated.
- The text is wrapped in an `<untrusted-tool-output>` tag with a random id per
  result, so the server's output cannot close the wrapper.
- A `filter` callable `(server, tool, text) -> text` runs before framing, if you
  pass one.

The wrapper makes a prompt injection harder. It does not make one impossible,
and the guard does not scan the text for injection strings.

## Mirrored parameters

A tool's schema can mark an argument with `x-mcp-header`, which copies the
model's value into an `Mcp-Param-*` request header. A tool whose annotations
break the rules (an invalid header name, two arguments mirrored to the same
header) is left out of `list_tools()` rather than repaired.

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
