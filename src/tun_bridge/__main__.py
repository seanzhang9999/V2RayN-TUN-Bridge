"""Dispatch the packaged executable to the GUI or background supervisor."""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--supervisor":
        del sys.argv[1]
        from tun_controller.mihomo_supervisor import main as supervisor_main

        return supervisor_main()

    from tun_gui.app import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
