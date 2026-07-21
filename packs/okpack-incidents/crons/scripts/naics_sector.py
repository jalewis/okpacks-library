"""Map detailed NAICS industry codes to their two-digit sector labels."""
from __future__ import annotations

_SECTORS = {
    "11": "Agriculture, forestry, fishing & hunting", "21": "Mining, quarrying, oil & gas",
    "22": "Utilities", "23": "Construction", "31": "Manufacturing", "32": "Manufacturing",
    "33": "Manufacturing", "42": "Wholesale trade", "44": "Retail trade", "45": "Retail trade",
    "48": "Transportation & warehousing", "49": "Transportation & warehousing",
    "51": "Information", "52": "Finance & insurance", "53": "Real estate",
    "54": "Professional, scientific & technical services", "55": "Management of companies",
    "56": "Administrative, support & waste services", "61": "Educational services",
    "62": "Health care & social assistance", "71": "Arts, entertainment & recreation",
    "72": "Accommodation & food services", "81": "Other services", "92": "Public administration",
}


def naics_sector(value: object) -> str | None:
    text = str(value or "").strip()
    return _SECTORS.get(text[:2]) if len(text) >= 2 and text[:2].isdigit() else None
