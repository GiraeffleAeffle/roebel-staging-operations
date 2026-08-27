#!/usr/bin/env python3
"""Run the protected E2E workbench GitOps handover.

The implementation is read from the exact protected Git revision named on the
command line and executed from those bytes.  The mutable worktree module is
never imported before that revision/blob check.  The implementation performs a
second complete protected-checkout verification when it builds its plan.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path


GIT_BIN = Path("/usr/bin/git")
IMPLEMENTATION_PATH = "scripts/workbench_baseline_handover.py"
REVISION = re.compile(r"^[0-9a-f]{40}$")


def _blocked(message: str, code: int = 2) -> int:
    print(f"workbench handover blocked: {message}", file=sys.stderr)
    return code


def _trusted_git(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    info = os.lstat(GIT_BIN)
    if not (
        stat.S_ISREG(info.st_mode)
        and not GIT_BIN.is_symlink()
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) & 0o022 == 0
        and os.access(GIT_BIN, os.X_OK)
    ):
        raise RuntimeError("trusted Git executable metadata invalid")
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(
        [str(GIT_BIN), "--no-pager", "--no-replace-objects", *args],
        env=environment,
        capture_output=True,
        timeout=10,
        check=False,
    )


def _revision_argument(argv: list[str]) -> str:
    for index, argument in enumerate(argv):
        if argument == "--expected-protected-revision":
            if index + 1 >= len(argv):
                raise ValueError("--expected-protected-revision requires a 40-character commit")
            value = argv[index + 1]
            break
        if argument.startswith("--expected-protected-revision="):
            value = argument.split("=", 1)[1]
            break
    else:
        raise ValueError("--expected-protected-revision is required before protected execution")
    if REVISION.fullmatch(value) is None:
        raise ValueError("protected revision must be 40 lowercase hex")
    return value


def _protected_implementation(*, root: Path, revision: str, local_path: Path) -> bytes:
    head = _trusted_git(["-C", str(root), "rev-parse", "HEAD"])
    if head.returncode != 0 or head.stdout.decode("utf-8", "replace").strip() != revision:
        raise RuntimeError("checked-out revision is not the expected protected revision")
    blob = _trusted_git(["-C", str(root), "show", f"{revision}:{IMPLEMENTATION_PATH}"])
    if blob.returncode != 0:
        raise RuntimeError("protected implementation blob unavailable")
    local_info = os.lstat(local_path)
    if not (
        stat.S_ISREG(local_info.st_mode)
        and not local_path.is_symlink()
        and local_info.st_uid == os.geteuid()
    ):
        raise RuntimeError("mutable worktree implementation metadata invalid")
    # Keep the explicit local comparison as a tamper-evident guard.  Execution
    # still uses ``blob``; it never imports or executes ``local_path``.
    if local_path.read_bytes() != blob.stdout:
        raise RuntimeError("mutable worktree implementation differs from protected Git blob")
    return blob.stdout


def _execute(argv: list[str]) -> int:
    revision = _revision_argument(argv)
    wrapper_path = Path(os.path.abspath(__file__))
    root = wrapper_path.parent.parent
    local_path = root / IMPLEMENTATION_PATH
    blob = _protected_implementation(root=root, revision=revision, local_path=local_path)
    globals_for_blob: dict[str, object] = {
        "__name__": "protected_workbench_baseline_handover",
        "__file__": str(local_path),
        "__package__": None,
        "__builtins__": __builtins__,
    }
    exec(compile(blob, f"{revision}:{IMPLEMENTATION_PATH}", "exec"), globals_for_blob, globals_for_blob)
    handover_error = globals_for_blob["HandoverError"]
    main = globals_for_blob["main"]
    try:
        return int(main(argv))  # type: ignore[operator]
    except handover_error as error:  # type: ignore[misc]
        return _blocked(str(error), 1)


if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.safe_path):
        raise SystemExit(_blocked("invoke with python3 -I"))
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print("usage: python3 -I scripts/handover-staging-workbench-baseline.py --expected-protected-revision REVISION [options]")
        raise SystemExit(0)
    try:
        raise SystemExit(_execute(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(_blocked(str(error))) from error
