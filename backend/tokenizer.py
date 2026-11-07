"""Replaceable tokenizer abstraction.

Swap `get_tokenizer()` to return the selected model's real tokenizer later;
anything with `count(text) -> int` works.
"""
import math
import re
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


_PIECE = re.compile(r"\d|[A-Za-z]+|[^\sA-Za-z\d]")


class LogAwareTokenizer:
    """Heuristic tokenizer calibrated against qwen3.5:0.8b on real Ollama counts.

    Qwen-style tokenizers emit one token per digit and mostly one per
    punctuation mark, so IP/timestamp-heavy logs cost ~1.34 chars/token, not
    the 3-5 of prose. Measured est/real: access log 0.96-0.97, sshd 0.96,
    prose 1.49 (over-estimating is the safe direction). `safety` covers the gap.
    Replace with the model's real tokenizer when one is available.
    """

    def __init__(self, safety: float = 1.1, word_chars_per_token: int = 4):
        self.safety, self.word = safety, word_chars_per_token

    def count(self, text: str) -> int:
        n = 0
        for m in _PIECE.finditer(text):
            s = m.group(0)
            n += math.ceil(len(s) / self.word) if s[0].isalpha() else 1
        return math.ceil(n * self.safety)


def get_tokenizer() -> Tokenizer:
    return LogAwareTokenizer()
