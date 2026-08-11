"""Provider plugins — one module per provider.

Empty until roadmap **R1.1** adds the first archetype, Google ``AIza``. The
package exists now so :class:`~keyreach.core.registry.ProviderRegistry` has
something to scan, and so a registry over a repository with no providers yet
loads cleanly instead of raising.

To add one, see "How to add a provider" in ``CLAUDE.md`` and the contract in
``keyreach/core/provider.py``. In short: subclass ``Provider``, set ``name``,
``category``, ``docs_url`` and ``rotation_guide_url``, implement ``detect``,
``validate`` and ``enumerate``, record a valid and an invalid fixture, and add a
credit entry if the plugin derives from prior art.

Two constraints apply to every module in this package:

* **No direct network access.** No ``httpx``, ``requests`` or ``socket`` import.
  All HTTP goes through the ``ProbeContext`` the engine provides, which is where
  rate limiting, record/replay, redaction and the read-only guard live. Ruff
  rejects the import at lint time and the ``network_isolation`` CI check
  (roadmap R0.9) rejects it again in CI.
* **Read-only probes only.** No writes, deletes, or spend.

Modules whose names begin with an underscore are treated as shared helpers and
are not scanned for plugins.
"""

from __future__ import annotations
