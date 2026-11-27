"""Run the standalone audit smoke test as part of pytest."""

import subprocess
import sys
from pathlib import Path


def test_audit_logging_without_framework_dependencies():
    """Emit audit JSON in a fresh Python process with site packages disabled."""
    smoke_test = Path(__file__).resolve().with_name("standalone.py")
    source_root = smoke_test.parents[2] / "src"
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import runpy, sys\nsys.path.insert(0, sys.argv[1])\nrunpy.run_path(sys.argv[2], run_name='__main__')",
            str(source_root),
            str(smoke_test),
        ],
        check=True,
    )
