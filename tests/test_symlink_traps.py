"""Tests for symlink escape and dangling symlink detection."""

from pathlib import Path

from sca_preflight.prescan import scan_workspace


def test_symlink_escape_and_dangling(tmp_path: Path) -> None:
    # Create an outside folder
    outside_dir = tmp_path / "outside_world"
    outside_dir.mkdir()
    secret_file = outside_dir / "passwords.txt"
    secret_file.write_text("secret")

    # Create workspace repo
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "main.py").write_text("print('hello')")

    # 1. Symlink escape pointing outside workspace
    escape_link = repo / "src" / "leak_outside"
    escape_link.symlink_to(secret_file)

    # 2. Dangling symlink pointing to non-existent target
    dangling_link = repo / "src" / "dead_link"
    dangling_link.symlink_to(repo / "non_existent_file.json")

    # Run scan
    report = scan_workspace(repo)

    # Assert escapes caught
    escapes = report.get("symlink_escapes", [])
    assert len(escapes) == 1
    assert escapes[0]["path"] == "src/leak_outside"
    assert "outside_world" in escapes[0]["target"]

    # Assert dangling caught
    danglings = report.get("dangling_symlinks", [])
    assert len(danglings) == 1
    assert danglings[0]["path"] == "src/dead_link"

    # Assert warnings surfaced
    warn_text = " ".join(report.get("warnings", []))
    assert "EXTERNAL_SYMLINK_ESCAPE" in warn_text
    assert "DANGLING_SYMLINK" in warn_text
