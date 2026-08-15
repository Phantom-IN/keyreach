"""A fake providers package with one invalid spec file (roadmap R2.8).

Paired with `tests/broken_providers`, which does the same job for two `.py`
plugins sharing a name. This package exercises the other way a registry load
can fail: a `.yml` file that does not satisfy `ProviderSpec` at all, so
`ProviderRegistry` must report which file is broken rather than propagating a
bare `pydantic.ValidationError`.
"""

from __future__ import annotations
