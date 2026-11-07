import io

import pytest
from fastapi.testclient import TestClient

from chunking import TokenBudget, chunk_lines, iter_lines
from main import app
from tokenizer import ApproxTokenizer

TOK = ApproxTokenizer(chars_per_token=1)  # 1 char == 1 token: easy to reason about


def chunks_of(text: str, budget: int):
    return list(chunk_lines(iter_lines(io.BytesIO(text.encode())), TOK, budget))


def test_budget_reserves_space():
    b = TokenBudget()
    assert b.chunk_tokens == 2048 - 450 - 250 - 512
    with pytest.raises(ValueError):
        TokenBudget(context_window=500).chunk_tokens


def test_line_numbers_preserved_and_contiguous():
    text = "\n".join(f"event {i}" for i in range(1, 51))
    cs = chunks_of(text, 60)
    assert len(cs) > 1
    nums = [n for c in cs for n, _ in c.lines]
    assert nums == list(range(1, 51))
    assert cs[0].start_line == 1 and cs[-1].end_line == 50
    for a, b in zip(cs, cs[1:]):
        assert b.start_line == a.end_line + 1


def test_original_text_recoverable_with_numbers():
    cs = chunks_of("alpha\nbeta\ngamma\n", 1000)
    assert cs[0].render() == "1: alpha\n2: beta\n3: gamma"


def test_chunks_respect_budget():
    text = "\n".join("x" * 10 for _ in range(100))
    for c in chunks_of(text, 50):
        assert c.token_count <= 50


def test_multiline_entry_not_split_when_it_fits():
    entry = "ERROR boom\n  at a.b(C.java:1)\n  at d.e(F.java:2)"
    text = "INFO ok\n" + entry + "\nINFO done"
    # budget fits the entry but not entry + neighbours
    cs = chunks_of(text, 60)
    spans = [(c.start_line, c.end_line) for c in cs]
    assert not any(s < 3 <= e for s, e in spans if s != 2), spans  # entry lines 2-4 stay together
    assert any(s <= 2 and e >= 4 for s, e in spans)


def test_oversized_entry_split_by_line():
    text = "ERROR big\n" + "\n".join(f"  frame {i}" for i in range(30))
    cs = chunks_of(text, 40)
    assert len(cs) > 1
    assert [n for c in cs for n, _ in c.lines] == list(range(1, 32))


def test_oversized_single_line_split_keeps_line_number():
    cs = chunks_of("a" * 500 + "\nnext", 50)
    assert all(c.token_count <= 50 for c in cs)
    long_pieces = [t for c in cs for n, t in c.lines if n == 1]
    assert "".join(long_pieces) == "a" * 500
    assert cs[-1].lines[-1] == (2, "next")


def test_crlf_and_invalid_utf8_tolerated():
    data = b"ok\r\nbad \xff\xfe bytes\r\n"
    cs = list(chunk_lines(iter_lines(io.BytesIO(data)), TOK, 100))
    assert [n for n, _ in cs[0].lines] == [1, 2]
    assert "\r" not in cs[0].lines[0][1]


def test_empty_input_yields_no_chunks():
    assert chunks_of("", 10) == []


# ---- API ----
client = TestClient(app)


def post(name, content, **kw):
    return client.post("/api/logs/upload", files={"file": (name, content)}, **kw)


def test_upload_ok_with_metadata_and_progress():
    r = post("a.log", "\n".join(f"line {i}" for i in range(1, 2000)))
    assert r.status_code == 200
    body = r.json()
    assert body["total_lines"] == 1999
    assert body["progress_percent"] == 100.0
    assert body["budget"]["chunk_tokens"] == 836
    assert body["chunks"][-1]["end_line"] == 1999
    assert body["chunks"][-1]["progress_percent"] == 100.0
    assert "text" not in body["chunks"][0]


def test_include_text():
    r = post("a.txt", "hello\nworld", params={"include_text": "true"})
    assert r.json()["chunks"][0]["text"] == "1: hello\n2: world"


@pytest.mark.parametrize(
    "name,content,code",
    [("a.exe", b"x", 415), ("noext", b"x", 415), ("a.log", b"", 400), ("a.log", b"ab\x00cd", 415)],
)
def test_invalid_uploads(name, content, code):
    assert post(name, content).status_code == code


def test_too_large(monkeypatch):
    import ingest

    monkeypatch.setattr(ingest, "MAX_UPLOAD_BYTES", 10)
    assert post("a.log", b"x" * 11).status_code == 413
