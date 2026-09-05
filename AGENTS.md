# AGENTS.md — prism-mcp-py

The Python port of
[`particle-academy/prism-mcp`](https://github.com/Particle-Academy/prism-mcp).
Read the shared agent guide in `prism-parity/docs/AGENTS.md` first: the
boundary, the satellite map, the rules that bind, and the review skills.

## Gates — run them on EXIT CODES

```sh
python -m ruff check .
python -m ruff format --check .
python -m mypy --strict src tests
python -m pytest
```

Never pipe a gate into `head`/`tail`/`grep` and read `$?` — that is the
FILTER's exit code, not the gate's. Redirect to a file, echo `$?`, then look.

## What this package holds

The trust boundary: an undeclared server is refused at DISCOVERY, definition
pinning, the result guard, and the x-mcp-header rules.

## The rule that binds every port here

**Faithful to the reference, or a DOCUMENTED divergence — never a quiet one.**
Where this port does something the reference does not, the reason is in the
code and in the envelope's port gaps register. A difference nobody wrote down
is drift, and drift is what this whole effort exists to prevent.

## Pins recorded before 2026-09-04 are invalid

`ToolDefinition.digest()` changed for EVERY tool. A tool with no description is
now digested with `description=""` rather than `None`, matching the reference,
so a pin an operator computed against a PHP deployment finally validates here —
and every pin computed against an older build of this port does not.

**What it looks like if nobody recomputes:** the pin is refused with
`tool_definition_changed`. That is the safe direction, and it is also exactly
what a real rug pull looks like, which is why the change is stated here rather
than left to be discovered. The answer is to recompute the digest and read the
description again, never to delete the pin.

The reference moved in the same change, in the other direction, for a different
reason — it no longer digests an empty map-typed field as `[]`. Both halves are
G-20 in the envelope's port gaps register, and both are pinned by
`prism-parity/suites/mcp-tool-digest`, where all thirteen rows now agree.
