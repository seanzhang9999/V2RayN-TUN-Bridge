import contextlib
import json
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch


@unittest.skipUnless(sys.platform == "win32", "Windows protection startup")
class GuardStartTests(unittest.TestCase):
    def test_certificate_failure_uses_another_resolver_through_1081(self):
        import guard_live as guard
        replies = [subprocess.CompletedProcess([], 35, b"", b"0x80092013"),
                   subprocess.CompletedProcess([], 0, json.dumps({
                       "Status": 0, "Answer": [{"type": 1, "data": "8.8.8.8"}]}).encode(), b"")]
        with patch.object(subprocess, "run", side_effect=replies) as run:
            self.assertEqual([str(ip) for ip in guard.g["resolve_node"]("vpn.example")], ["8.8.8.8"])
        for call in run.call_args_list:
            args = call.args[0]
            self.assertEqual(args[args.index("--proxy")+1], "socks5h://127.0.0.1:1081")
            self.assertEqual(args[args.index("--noproxy")+1], "")
            self.assertNotIn("--insecure", args)
            self.assertNotIn("--ssl-no-revoke", args)
        self.assertIn("cloudflare-dns.com", run.call_args.args[0][-1])

    def test_failed_combined_start_never_installs_filters_or_reports_ready(self):
        import guard_live as guard
        kernel = Mock()
        kernel.CreateMutexW.return_value = 1
        kernel.WaitForSingleObject.return_value = 0
        with (patch.object(guard.c.windll, "kernel32", kernel),
              patch.object(guard, "action_lock", contextlib.nullcontext),
              patch.dict(guard.g, read_node_details=lambda: ("xray", "node.example", (443, 6)),
                         resolve_node=Mock(side_effect=ValueError("DNS unavailable"))),
              patch.object(guard, "verify_core"), patch.object(guard, "config_path"),
              patch.object(guard, "direct_networks"), patch.object(guard, "install") as install,
              patch.object(guard, "acknowledge") as ready):
            with self.assertRaisesRegex(RuntimeError, "DNS unavailable"):
                guard.activate(None, for_tun=True)
        install.assert_not_called()
        ready.assert_not_called()
