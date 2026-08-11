"""A fake providers package, used to exercise the registry (roadmap R0.4).

The registry is parameterised by package name precisely so its tests never have
to touch ``keyreach.providers`` or mutate global state — each test builds a
``ProviderRegistry`` over this package or over one of the deliberately broken
packages beside it.

Module names here are chosen so that **alphabetical module order differs from
alphabetical provider order**. ``zulu.py`` defines the provider named ``alpha``
and ``alpha.py`` defines ``zebra``, so a registry that returned providers in
import order rather than sorting by name would fail the ordering test instead of
passing by accident.
"""

from __future__ import annotations
