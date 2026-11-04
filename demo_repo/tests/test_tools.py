import os

from filedesk import tools


def test_file_size_reports_bytes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.mkdir("uploads")
    with open("uploads/report.txt", "w") as f:
        f.write("hello world")
    assert tools.file_size("report.txt") == 11


def test_missing_file_returns_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.mkdir("uploads")
    assert tools.file_size("nope.txt") is None


def test_safe_name():
    assert tools.safe_name("a.txt")
    assert not tools.safe_name("../etc/passwd")
