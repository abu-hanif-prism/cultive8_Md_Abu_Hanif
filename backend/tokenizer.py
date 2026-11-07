"""Replaceable tokenizer abstraction.

Swap `get_tokenizer()` to return the selected model's real tokenizer later;
anything with `count(text) -> int` works.
"""
import math
from typing import Protocol


class Tokenizer(Protocol):
    def count(self, text: str) -> int: ...


class ApproxTokenizer:
    """Placeholder: estimates tokens as len/chars_per_token.

    Defaults to 3 chars/token, deliberately conservative for log text
    (IPs, hex, paths tokenize poorly), so chunks err on the small side.
    """

    def __init__(self, chars_per_token: float = 3.0):
        if chars_per_token <= 0:
            raise ValueError("chars_per_token must be > 0")
        self.chars_per_token = chars_per_token

    def count(self, text: str) -> int:
        return math.ceil(len(text) / self.chars_per_token) if text else 0


def get_tokenizer() -> Tokenizer:
    return ApproxTokenizer()
