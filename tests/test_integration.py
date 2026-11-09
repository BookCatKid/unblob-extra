"""End-to-end regressions copied from the four upstream contribution PRs.

Exercise the actual unblob command with this collection installed via pluggy,
then verify every extracted fixture file byte-for-byte against the source PR.
"""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "integration"
CASES = sorted(FIXTURES.rglob("__input__"))


def _files(root: Path) -> dict[str, str]:
    """Return a hash-based file tree, ignoring placeholder files."""
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name != ".gitkeep"
    }


@pytest.mark.parametrize(
    "inputs",
    [pytest.param(path, id=str(path.parent.relative_to(FIXTURES))) for path in CASES],
)
def test_end_to_end_extraction(inputs: Path, tmp_path: Path):
    expected = _files(inputs.parent / "__output__")
    output = tmp_path / "output"
    output.mkdir()
    exe = Path(sys.executable).with_name("unblob")
    for inp in sorted(inputs.iterdir()):
        cmd = [
            str(exe),
            "--no-sandbox",
            "--keep-extracted-chunks",
            "--randomness-depth",
            "0",
            "--process-num",
            "1",
            "--extract-dir",
            str(output),
            "--log",
            str(tmp_path / "unblob.log"),
            str(inp),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, (
            f"{inp}: unblob exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    actual = _files(output)
    assert actual == expected, (
        f"{inputs.parent}: file-tree/hash mismatch\n"
        f"missing={sorted(expected.keys() - actual.keys())}\n"
        f"extra={sorted(actual.keys() - expected.keys())}\n"
        f"changed={sorted(k for k in expected.keys() & actual.keys() if expected[k] != actual[k])}"
    )
