"""Shared actor roster and sourced mention decisions; not an actor-name allowlist."""
from __future__ import annotations

import re
from pathlib import Path

try:
    from okengine.actor_identity import actor_identity_error
except ImportError as exc:
    raise RuntimeError("actor roster requires the installed OKEngine actor identity guard") from exc

# Single-word codename suffixes / generics that over-match when they stand alone. A MULTI-word alias
# containing one (e.g. "velvet tempest", "volt typhoon") is distinctive and kept — only the bare token
# is dropped. Vendor taxonomies: CrowdStrike animals, Microsoft weather, Mandiant/Secureworks generics.
_GENERIC = {
    "group", "team", "unknown", "gang", "crew", "actor", "apt", "the",
    "spider", "panda", "bear", "kitten", "tiger", "buffalo", "jackal", "ox", "lynx", "wolf",
    "chollima", "leopard", "crane", "hawk", "pig", "spindle",
    "tempest", "typhoon", "sleet", "storm", "blizzard", "cyclone", "sandstorm", "hail", "dust", "flood",
}

# These legacy vocabulary sets now select occurrences requiring local actor/action context.
# They do not ban actor identities: e.g. "Silence targeted banks" remains supported.
_ENGLISH_COMMON = frozenset("""
access agent agents alert anchor anvil apex armor arrow attack attacker attackers aurora
autonomous autumn avalanche azure beacon blaze botnet breach bridge bunker campaign cascade cedar
chimera chisel cipher citadel cleaver client cobalt cobra comet comment condor cortex cosmos
criminal criminals crimson current cypress dagger dragon drifter eagle eclipse ember equation
exploit fabric falcon ferret fortress frost fusion galaxy gateway ghost glitch golden granite
griffin hacker hammer harbor hidden hollow hornet hunter hydra intruder ivory javelin keeper
kraken lance laurel legacy locust machete malware mantis marble matrix meteor mirage monsoon
nebula needle nettle network nexus nomad onyx oracle origin otter patch phantom pliers portal
prism pulse quantum quartz quiver rampart ranger ransomware rapier raven reaper relay remote
report saber scarlet scorpion secure seeker sentinel serpent server shade shadow shield signal
silence silver socket specter spectre sphinx spring static stealth summer surge switch target
tempest thorn thread threat thunder titan tornado torrent tunnel typhoon update vault vector venom
victim violet viper voltage warden weasel willow winter wizard wrench zenith
""".split())

# MULTI-WORD descriptions minted as actor names. The single-token rule above cannot reach these,
# and a compositional rule ("every word is generic") CANNOT be used: real codenames are built from
# common words too -- "Comment Crew" is APT1 and both its words are in the lists above, as are
# "spider" and "typhoon" in Scattered Spider and Volt Typhoon. Word composition cannot tell a NAME
# from a DESCRIPTION, so this is a curated phrase list, matched whole and lowercased.
#
# Every entry below was a live actor page on a real corpus. The cost is not a bad row on a board:
# `recent_news` also ranks the actor-assessment-priority queue, so "Threat Actor" scored 58 matches
# against 1 cited source and was scheduled for analysis ahead of every real adversary.
_GENERIC_PHRASE = frozenset("""
ai agent|ai agents|attack group|autonomous llm agent|cyber criminals|cybercriminal group
hacker group|llm agent|llm agents|malware campaign|ransomware gang|ransomware gangs
threat actor|threat actors|threat group|unknown actor|unknown threat actor
""".strip().replace("\n", "|").split("|"))

# Product/brand-like aliases need the same local role context as common-word names.
# A contrary alias occurrence does not invalidate independently supported primary names.
_BRAND_COMMON = frozenset("""
adobe akamai alibaba amazon android apple azure baidu chrome cisco citrix cloudflare crowdstrike dell
discord docker fastly fedora fireeye firefox fortinet github gitlab google huawei ibm intel juniper
kaspersky linkedin linux mandiant mcafee meta microsoft mozilla netflix nginx nvidia okta openai
oracle outlook paypal proton pulse rackspace reddit redhat safari samsung sharepoint slack snowflake
sonicwall splunk symantec telegram tencent tesla twitter ubuntu vmware whatsapp windows yahoo zoom
""".split())


def terms_for(fm: dict) -> set:
    """Candidate names; source occurrence context decides whether ambiguous terms count."""
    out = set()
    for nm in [fm.get("title")] + (fm.get("aliases") or []):
        s = str(nm or "").strip().lower()
        if not s:
            continue
        if s in _GENERIC_PHRASE:
            continue                                     # a description, not a name -> matches everything
        if " " not in s and s in _GENERIC:
            continue                                     # bare taxonomy suffix / generic role
        if len(s) >= 2:
            out.add(s)
    return out



def eligible(fm: dict, body: str, wiki: Path | None = None) -> bool:
    return (fm.get("type") == "actor"
            and str(fm.get("status") or "").strip().casefold() != "tombstoned"
            and not fm.get("redirect_to")
            and actor_identity_error(str(fm.get("title") or fm.get("name") or ""), body) is None
            and (wiki is None or source_identity_error(wiki, fm) is None))


def source_identity_error(wiki: Path, fm: dict) -> str | None:
    """Read only the candidate's cited original sources through the shared writer adapter."""
    from _okf_write import _actor_source_error
    return _actor_source_error(wiki, fm)


def original_reporting(text: str) -> str:
    """Generated roster-link appendices are outputs, never fresh evidence of a mention."""
    return re.sub(r"(?m)^## Actors named in this report\s*\n(?:\s*- \[\[[^\n]+\]\]\s*\n?)*", "", text)


def mention_supported(text: str, match: re.Match) -> bool:
    term = match.group(0)
    before = text[max(0, match.start() - 120):match.start()]
    after = text[match.end():match.end() + 120]
    if re.match(r"\s+(?:is|was|are)\s+not\s+(?:(?:a|an|the)\s+)?(?:actor|threat actor|intrusion set|group)\b", after, re.I):
        return False
    # A local grammatical actor role can support short/common names; a negated role cannot.
    role = re.match(r"\s*(?:(?:is|was|are)\s+(?:a\s+|an\s+|the\s+)?|(?:threat\s+)?)"
                    r"(?:threat actor|intrusion set|threat group|group|gang|crew|operators?)\b", after, re.I)
    tracked = re.search(r"\b(?:actor|group|gang|intrusion set)\s+(?:(?:known|tracked)\s+as\s+|called\s+|named\s+)?$", before, re.I)
    action = re.match(r"\s+(?:targeted|targets|compromised|attacked|infiltrated|conducted|launched|stole|exfiltrated)\b", after, re.I)
    # These are mentions of an eligible identity, not allegations of perpetration.
    mentioned = re.match(r"\s+(?:denied\s+(?:any\s+)?responsibility|was\s+(?:attacked|targeted|victimized)|"
                         r"suffered\s+(?:a\s+)?(?:data\s+)?breach)\b", after, re.I)
    if role or tracked or action or mentioned:
        return True
    if re.search(r"\b(?:critical|high|severe|significant|major|serious)\s+threat$", term, re.I):
        return False
    if re.search(r"\bthreat$", term, re.I):
        if re.match(r"[- ](?:risk|score|level|rating)\b", after, re.I) or re.search(r"\b(?:a|an)\s+$", before, re.I):
            return False
    if len(term.strip()) < 5 or term.casefold() in (_ENGLISH_COMMON | _BRAND_COMMON | _GENERIC):
        return False
    return True


def mentions(text: str, term_to_actor: dict[str, str]) -> set[str]:
    if not term_to_actor:
        return set()
    text = original_reporting(text)
    rx = re.compile(r"(?<!\w)(" + "|".join(re.escape(term) for term in sorted(term_to_actor, key=len, reverse=True)) + r")(?!\w)", re.I)
    return {term_to_actor[match.group(0).casefold()] for match in rx.finditer(text)
            if mention_supported(text, match)}


def explicit_mention_supported(text: str, terms: set[str]) -> bool:
    """Preserve explicit legacy mentions unless original reporting contradicts the name sense.

    This is not a universal new positive-language gate on previously imported structured claims.
    Generated link appendices cannot override a contrary occurrence in the original report.
    """
    original = text
    text = original_reporting(text)
    occurrences = [match for term in terms for match in re.finditer(r"(?<!\w)" + re.escape(term) + r"(?!\w)", text, re.I)]
    if not occurrences and text != original:
        return False
    return not occurrences or any(mention_supported(text, match) for match in occurrences)
