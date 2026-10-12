# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Texts in French and English, and locale-aware dates.

Texts come from two places: ``locales/<lang>.json`` for the interface and the
report, and the ``messages`` of each extension for the checks. A missing text
falls back to English, then to its key, so a forgotten translation shows up
plainly instead of breaking a page.

Parameters are written ``{name}``. A parameter whose name ends with ``_on``
holds an ISO date (``2026-10-21``) and is written out in the reader's language
(``21 octobre 2026``). A number can carry its noun: ``{days:jour|jours}``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import date
from functools import cache
from pathlib import Path

LOCALES = ("fr", "en")
_DIR = Path(__file__).parent / "locales"

MONTHS = {
    "fr": ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre",
           "octobre", "novembre", "décembre"],
    "en": ["January", "February", "March", "April", "May", "June", "July", "August", "September",
           "October", "November", "December"],
}


@cache
def interface_texts(lang: str) -> dict[str, str]:
    return json.loads((_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def fmt_date(value: date | str, lang: str) -> str:
    d = date.fromisoformat(value) if isinstance(value, str) else value
    if lang == "fr":
        return f"{'1er' if d.day == 1 else d.day} {MONTHS['fr'][d.month - 1]} {d.year}"
    return f"{d.day} {MONTHS['en'][d.month - 1]} {d.year}"


class _Params(dict):
    """Leaves unknown ``{placeholders}`` as they are instead of raising KeyError."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


class _Count(int):
    """A number that can agree with its noun: ``{days:jour|jours}`` gives "1 jour", "9 jours".

    French uses the singular for 0 and 1, English for 1 only."""

    lang = "en"

    def __format__(self, spec: str) -> str:
        if "|" not in spec:
            return super().__format__(spec)
        singular, plural = spec.split("|", 1)
        one = int(self) in (0, 1) if self.lang == "fr" else int(self) == 1
        return f"{int(self)} {singular if one else plural}"


def _count(value: int, lang: str) -> _Count:
    number = _Count(value)
    number.lang = lang
    return number


def _param(name: str, value: object, lang: str) -> object:
    if name.endswith("_on") and value:
        return fmt_date(str(value), lang)
    if isinstance(value, int) and not isinstance(value, bool):
        return _count(value, lang)
    return value


class Catalog:
    """Every text of the application, interface and extensions together."""

    def __init__(self, extension_texts: Callable[[str], Mapping[str, str]] = lambda lang: {}):
        self._texts = {lang: {**extension_texts(lang), **interface_texts(lang)} for lang in LOCALES}

    def has(self, lang: str, key: str) -> bool:
        return key in self._texts.get(lang, {})

    def text(self, lang: str, key: str, params: Mapping[str, object] | None = None) -> str:
        lang = lang if lang in LOCALES else "en"
        template = self._texts[lang].get(key) or self._texts["en"].get(key) or key
        if not params:
            return template
        values = _Params({name: _param(name, value, lang) for name, value in params.items()})
        return template.format_map(values)

    def first(self, lang: str, keys: list[str], params: Mapping[str, object] | None = None) -> str:
        """The first of ``keys`` that exists (e.g. a specific wording, then a general one)."""
        for key in keys:
            if self.has(lang, key) or self.has("en", key):
                return self.text(lang, key, params)
        return keys[-1]


def pick_locale(accept_language: str | None, default: str = "fr") -> str:
    """The first supported language of the browser's Accept-Language header."""
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in LOCALES:
            return code
    return default
