# Sigma JSON Schema — provenance

```text
File       sigma-detection-rule-schema.json
Source     https://github.com/SigmaHQ/sigma-specification
Path       json-schema/sigma-detection-rule-schema.json
Commit     ba9251aa834b   (2026-06-09)
Retrieved  2026-09-07, via the GitHub API
Size       8,922 bytes
SHA-256    EB95DDB1BC2503145A6E84511E38990F... (first 32 characters)
Draft      https://json-schema.org/draft/2020-12/schema#
```

Pinned here on purpose: validation that depends on the network is not reproducible, and the
CI result would start to depend on the day it runs. Updating is a deliberate action, with the
specification commit recorded above.

## Licensing

The Sigma specification and SigmaHQ's **rule content** carry different terms. This file is
the specification — schema, not detection. No SigmaHQ rule has been copied into this
repository. See `docs/LICENSING.md`.

## What this schema validates, and what it does not

```text
VALIDATES        rule shape: fields, types, formats, permitted values for level and status
DOES NOT CHECK   whether pySigma compiles the rule for a backend
DOES NOT CHECK   whether the rule detects anything
DOES NOT CHECK   SigmaHQ repository conventions (file name, tag order, and so on)
```

Fields the schema requires: only `title`, `logsource`, `detection`. This project requires
more than that in its own gate — including a non-empty `falsepositives`.
