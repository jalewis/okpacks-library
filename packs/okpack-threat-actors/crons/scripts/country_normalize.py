#!/usr/bin/env python3
"""Canonical country values for actor attribution fields.

Storage uses ISO 3166-1 alpha-2 codes.  Ambiguous geopolitical descriptions are not
countries and therefore return ``None`` instead of being promoted to attribution.
"""
from __future__ import annotations

_CODES = {
    "algeria": "DZ", "austria": "AT", "belarus": "BY", "brazil": "BR",
    "china": "CN", "egypt": "EG", "france": "FR", "india": "IN",
    "indonesia": "ID", "iran": "IR", "iraq": "IQ", "israel": "IL",
    "italy": "IT", "kazakhstan": "KZ", "kenya": "KE", "lebanon": "LB",
    "libya": "LY", "malaysia": "MY", "morocco": "MA", "nigeria": "NG",
    "north korea": "KP", "democratic people's republic of korea": "KP",
    "pakistan": "PK", "palestine": "PS", "romania": "RO", "russia": "RU",
    "russian federation": "RU", "singapore": "SG", "south korea": "KR",
    "republic of korea": "KR", "spain": "ES", "syria": "SY", "taiwan": "TW",
    "tunisia": "TN", "turkey": "TR", "türkiye": "TR", "ukraine": "UA",
    "united arab emirates": "AE", "uae": "AE", "united kingdom": "GB",
    "uk": "GB", "united states": "US", "united states of america": "US",
    "usa": "US", "vietnam": "VN",
}


def normalize_country(value: object) -> str | None:
    """Return a canonical alpha-2 country code, or None for unknown/ambiguous input."""
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else None
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) == 2 and text.isalpha():
        return text.upper()
    return _CODES.get(text.casefold())
