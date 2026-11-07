import pytest


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Every test gets its own SQLite DB / uploads directory."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
