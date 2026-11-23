"""Dispatch the packaged executable to the GUI or background supervisor."""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--confirm-restart":
        from tun_controller.restart_consent import confirm_restart
        return 0 if confirm_restart("手动请求重启 TUN，重新读取节点、路由与网络。") else 10
    if len(sys.argv) > 1 and sys.argv[1] == "--supervisor":
        del sys.argv[1]
        from tun_controller.mihomo_supervisor import main as supervisor_main

        return supervisor_main()

    from tun_gui.app import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
