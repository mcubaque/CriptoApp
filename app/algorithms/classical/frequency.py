"""Shared frequency-analysis engine used by shift/affine/substitution cracking.
Reference tables lifted directly from lectura-fundamental.md section 6.
"""
from __future__ import annotations

from app.core.step_trace import StepTable
from app.core.text_utils import ALPHABET

# Monogram frequency ranking, most to least frequent, per the reading:
# E (0.120); T,A,O,I,N,S,H,R (0.06-0.09); D,L (0.04);
# C,U,M,W,F,G,Y,P,B (0.015-0.028); V,K,J,X,Q,Z (<0.01)
ENGLISH_FREQUENCY_ORDER = [
    "E", "T", "A", "O", "I", "N", "S", "H", "R",
    "D", "L",
    "C", "U", "M", "W", "F", "G", "Y", "P", "B",
    "V", "K", "J", "X", "Q", "Z",
]

ENGLISH_APPROX_PROB = {
    "E": 0.120,
    **{ch: 0.075 for ch in "TAOINSHR"},
    **{ch: 0.040 for ch in "DL"},
    **{ch: 0.020 for ch in "CUMWFGYPB"},
    **{ch: 0.005 for ch in "VKJXQZ"},
}

COMMON_DIGRAMS = [
    "TH", "HE", "IN", "ER", "AN", "RE", "ED", "ON", "ES", "ST",
    "EN", "AT", "TO", "NT", "HA", "ND", "OU", "EA", "NG", "AS",
    "OR", "TI", "IS", "ET", "IT", "AR", "TE", "SE", "HI", "OF",
]

COMMON_TRIGRAMS = [
    "THE", "ING", "AND", "HER", "ERE", "ENT", "THA", "NTH", "WAS", "ETH", "FOR", "DTH",
]

COMMON_WORDS = ["THE", "AND", "THAT", "HAVE", "FOR", "NOT", "WITH", "YOU", "THIS"]

# Short common English words. Digram/trigram scoring alone is unreliable on very
# short ciphertexts (a 3-4 letter candidate rarely contains a full common digram
# by anything other than coincidence) -- an exact whole-word match is a much
# stronger signal, so it gets a bigger bonus in english_likeness_score below.
COMMON_SHORT_WORDS = [
    "A", "I", "AM", "AN", "AS", "AT", "BE", "BY", "DO", "GO", "HE", "IF", "IN",
    "IS", "IT", "ME", "MY", "NO", "OF", "ON", "OR", "SO", "TO", "UP", "US", "WE",
    "ALL", "AND", "ANY", "ARE", "BUT", "CAN", "DAY", "DOG", "CAT", "GET", "HAD",
    "HAS", "HER", "HIM", "HIS", "HOW", "MAN", "NEW", "NOT", "NOW", "OLD", "ONE",
    "OUR", "OUT", "RUN", "SAW", "SAY", "SEE", "SHE", "SUN", "THE", "TOO", "TWO",
    "USE", "WAS", "WAY", "WHO", "WHY", "YES", "YOU",
]


def count_letter_frequencies(text: str) -> dict[str, int]:
    counts = {ch: 0 for ch in ALPHABET}
    for ch in text:
        if ch in counts:
            counts[ch] += 1
    return counts


def frequency_table(text: str) -> StepTable:
    counts = count_letter_frequencies(text)
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    rows = [[letter, n] for letter, n in ordered if n > 0]
    return StepTable(columns=["Letra", "Ocurrencias"], rows=rows)


def frequency_chart(text: str) -> dict:
    """Bar-chart spec for the letter-frequency table, ready for the template
    to render directly (percentages precomputed here, not in Jinja)."""
    counts = count_letter_frequencies(text)
    ordered = [(l, n) for l, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])) if n > 0]
    max_n = max((n for _, n in ordered), default=1)
    return {
        "type": "bar",
        "bars": [{"label": l, "value": n, "pct": round(n / max_n * 100)} for l, n in ordered],
    }


def most_frequent_letters(text: str, top_n: int = 5) -> list[str]:
    counts = count_letter_frequencies(text)
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [letter for letter, n in ordered if n > 0][:top_n]


def english_likeness_score(text: str) -> int:
    """A crude, dependency-free heuristic: count occurrences of common
    digrams/trigrams/short words. Higher is more plausibly English."""
    score = 0
    for gram in COMMON_TRIGRAMS:
        score += text.count(gram) * 3
    for gram in COMMON_DIGRAMS:
        score += text.count(gram) * 2
    for word in COMMON_WORDS:
        score += text.count(word) * 5
    # Exact whole-text match against a common short word is a much stronger
    # signal than an accidental digram hit -- important for short ciphertexts
    # (a handful of letters), where digram/trigram scoring alone is too noisy
    # to reliably beat coincidental matches.
    if text in COMMON_SHORT_WORDS:
        score += 10
    return score
