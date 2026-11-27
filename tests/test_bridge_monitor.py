import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform == 'win32', 'Windows guard monitor')
class MonitorTests(unittest.TestCase):
    def setUp(self):
        import bridge_monitor as m
        self.m = m
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        paths = patch.multiple(m, ROOT=root, HISTORY=root/'ring.json', SAVED=root/'incident.json')
        paths.start()
        self.addCleanup(paths.stop)

    def test_worker_expires_samples_and_preserves_recent_restart_history(self):
        m = self.m
        m.save(m.HISTORY, {'rows':[{'at':90}, {'at':101}]})
        event = threading.Event()
        # End after the first completed worker iteration.
        with patch.object(m, 'WireCounts'), patch.object(m.time, 'time', return_value=400), \
                patch.object(m, 'collect', return_value={'at':400}), \
                patch.object(event, 'wait', side_effect=lambda _: event.set()):
            m.watch(None, event)
        self.assertEqual([101,400], [r['at'] for r in m.read(m.HISTORY)['rows']])

    def test_stop_then_disable_keeps_the_pre_stop_window(self):
        m = self.m
        with patch.object(m.time, 'time', return_value=101):
            m.save(m.HISTORY, {'session':1,'rows':[{'at':100,'tun':23}]})
            m.preserve_on_stop('停止 TUN')
        with patch.object(m.time, 'time', return_value=151):
            m.save(m.HISTORY, {'session':1,'rows':[{'at':150,'tun':None}]})
            m.preserve_on_stop('关闭保护')
            self.assertEqual(m.read(m.SAVED)['rows'][0]['at'], 100)
            m.preserve('手动保留')
            self.assertEqual(m.read(m.SAVED)['rows'][0]['at'], 150)

    def test_unconfirmed_guard_skips_external_probes(self):
        from types import SimpleNamespace
        m = self.m
        m.save(m.ROOT/'guard-heartbeat.json', {'on':True,'at':1})
        with patch.object(m,'socks_udp',return_value='拒绝 (7)'), \
                patch.object(m,'link_snapshot',return_value={'tun':{'index':7}}), \
                patch.object(m,'local_dns',return_value='有应答'), \
                patch.object(m,'proxy_https') as proxy, patch.object(m,'tunnel_tls') as tunnel:
            row=m.collect(SimpleNamespace(tun_luid=lambda:123),90,100)
            self.assertEqual(row['guard'],'未确认')
            self.assertEqual(row['udp1081'],'拒绝 (7)')
            tunnel.assert_not_called()
            proxy.assert_not_called()

    def test_core_errors_are_timed_and_exclude_url_queries(self):
        m = self.m
        (m.ROOT/'mihomo-runtime-stdout.log').write_text(
            'time="1970-01-01T00:01:40Z" level=warning msg="[UDP] --> demo.test:443 error: can\'t resolve ip: https://example.test/?key=private"\n'
            'time="1970-01-01T00:05:00Z" level=error msg="late"\n')
        events=m.core_events(70,110)
        self.assertEqual(len(events),1)
        self.assertEqual(events[0][1:],['DNS 解析失败','demo.test:443'])
        self.assertNotIn('private',json.dumps(events))
