"""Text normalization and letter<->integer mapping shared by the classical
ciphers (alphabet A..Z mapped to 0..25, matching the reading's convention).
"""
from __future__ import annotations

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_SIZE = 26


def normalize_text(text: str) -> str:
    """Uppercase, keep only A-Z. Anything else (spaces, punctuation, digits)
    is stripped, mirroring how the reading's examples treat plaintext."""
    return "".join(ch for ch in text.upper() if ch.isalpha() and ch in ALPHABET)


def letter_to_int(ch: str) -> int:
    return ALPHABET.index(ch.upper())


def int_to_letter(n: int) -> str:
    return ALPHABET[n % ALPHABET_SIZE]


def text_to_ints(text: str) -> list[int]:
    return [letter_to_int(ch) for ch in text]


def ints_to_text(nums: list[int]) -> str:
    return "".join(int_to_letter(n) for n in nums)


def chunk(seq: str, size: int, pad_char: str = "X") -> list[str]:
    """Split into fixed-size blocks, padding the last block with pad_char."""
    blocks = []
    for i in range(0, len(seq), size):
        block = seq[i:i + size]
        if len(block) < size:
            block = block + pad_char * (size - len(block))
        blocks.append(block)
    return blocks
