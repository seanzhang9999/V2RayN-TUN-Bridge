"""Cross-process runtime ownership, released by Windows even after a crash."""
from pathlib import Path
import msvcrt


class RuntimeLease:
    def __init__(self, root: Path):
        self.root = root
        self.stream = None

    def __enter__(self) -> bool:
        self.root.mkdir(parents=True, exist_ok=True)
        self.stream = (self.root / "supervisor.lock").open("a+b")
        self.stream.seek(0, 2)
        if self.stream.tell() == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.stream.close()
            self.stream = None
            return False
        return True

    def __exit__(self, *_args):
        if self.stream is not None:
            # Do not unlink: other launchers must continue locking the same file.
            self.stream.close()
            self.stream = None
