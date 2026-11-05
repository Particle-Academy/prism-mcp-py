# Changelog

## 0.3.0

- **Breaking:** empty trust allowlists raise before discovery, with a distinct
  message from missing trust. Wildcard empty-server discovery remains valid.
- Report missing explicitly configured tools through optional sync or async
  `on_diagnostic`, or a native `McpDiagnosticWarning`. Diagnostics contain only
  configured names; callback failures propagate without offering tools.
- **Behavior change:** increase the default result cap from 65,536 to 262,144
  UTF-8 bytes, matching PHP. Explicit limits and disabled limits retain their
  meaning; oversized success and error results are refused.
- **Breaking:** replace silently dropped nontext content with ordered omission
  markers. Forward text only from parts labelled `type: "text"`.
- **Breaking:** invalid mirrored annotations on explicitly trusted tools raise;
  wildcard exclusions remain inspectable through `excluded()`.
- **Breaking:** only absent or literal `False` `isError` reports success. All
  other present values, including `None`, report guarded tool failure.
- No HTTP transport, cache or mirrored header value encoding change.
