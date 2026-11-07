"""Streaming log chunker that preserves original line numbers."""
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from tokenizer import Tokenizer

# A line is a continuation of the previous entry if it is indented or looks
# like a stack-trace tail. Everything else starts a new entry.
_CONTINUATION = re.compile(r"^(\s+|Caused by:|\.\.\. \d+ more|Traceback )")


@dataclass(frozen=True)
class TokenBudget:
    context_window: int = 2048
    system_prompt: int = 450
    context: int = 250
    output: int = 512

    @classmethod
    def from_env(cls) -> "TokenBudget":
        d = cls()
        g = lambda k, v: int(os.getenv(k, v))
        return cls(
            g("CONTEXT_WINDOW_TOKENS", d.context_window),
            g("SYSTEM_PROMPT_RESERVE_TOKENS", d.system_prompt),
            g("CONTEXT_RESERVE_TOKENS", d.context),
            g("OUTPUT_RESERVE_TOKENS", d.output),
        )

    @property
    def chunk_tokens(self) -> int:
        """Tokens available for log content in one chunk."""
        n = self.context_window - self.system_prompt - self.context - self.output
        if n < 1:
            raise ValueError("Reserved tokens leave no room for log content")
        return n


@dataclass
class Chunk:
    index: int
    lines: list[tuple[int, str]] = field(default_factory=list)  # (original line no, text)
    token_count: int = 0
    end_byte: int = 0  # bytes of the file consumed once this chunk is complete

    @property
    def start_line(self) -> int:
        return self.lines[0][0]

    @property
    def end_line(self) -> int:
        return self.lines[-1][0]

    def render(self) -> str:
        return "\n".join(render_line(n, t) for n, t in self.lines)


def render_line(number: int, text: str) -> str:
    return f"{number}: {text}"


def _split_long(text: str, number: int, budget: int, tok: Tokenizer) -> Iterator[str]:
    """Split a single over-budget line into pieces that each fit."""
    if tok.count(render_line(number, text)) <= budget or len(text) <= 1:
        yield text
        return
    mid = len(text) // 2
    yield from _split_long(text[:mid], number, budget, tok)
    yield from _split_long(text[mid:], number, budget, tok)


def iter_lines(binary_file, errors: str = "replace") -> Iterator[tuple[int, str, int]]:
    """Yield (line_number, text, end_byte_offset) lazily; 1-based numbers."""
    offset = 0
    for n, raw in enumerate(binary_file, start=1):
        offset += len(raw)
        yield n, raw.decode("utf-8", errors=errors).rstrip("\r\n"), offset


def _entries(lines: Iterable[tuple[int, str, int]]) -> Iterator[list[tuple[int, str, int]]]:
    entry: list[tuple[int, str, int]] = []
    for item in lines:
        if entry and not _CONTINUATION.match(item[1]):
            yield entry
            entry = []
        entry.append(item)
    if entry:
        yield entry


def chunk_lines(
    lines: Iterable[tuple[int, str, int]], tok: Tokenizer, budget_tokens: int
) -> Iterator[Chunk]:
    """Group lines into chunks of <= budget_tokens, keeping entries whole when
    they fit. An entry larger than the budget is split by line; a single line
    larger than the budget is split into pieces sharing the same line number.
    """
    if budget_tokens < 1:
        raise ValueError("budget_tokens must be >= 1")
    chunk = Chunk(index=0)

    def flush() -> Iterator[Chunk]:
        nonlocal chunk
        if chunk.lines:
            yield chunk
            chunk = Chunk(index=chunk.index + 1)

    def add(number: int, text: str, end_byte: int) -> Iterator[Chunk]:
        nonlocal chunk
        cost = tok.count(render_line(number, text)) + 1  # +1 for newline
        if chunk.lines and chunk.token_count + cost > budget_tokens:
            yield from flush()
        chunk.lines.append((number, text))
        chunk.token_count += cost
        chunk.end_byte = end_byte

    for entry in _entries(lines):
        cost = sum(tok.count(render_line(n, t)) + 1 for n, t, _ in entry)
        if chunk.lines and chunk.token_count + cost > budget_tokens:
            yield from flush()  # start the entry on a fresh chunk
        for n, text, end_byte in entry:
            for piece in _split_long(text, n, budget_tokens - 1, tok):
                yield from add(n, piece, end_byte)
    yield from flush()
