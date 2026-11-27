import unittest
from unittest.mock import patch

import tun_activity


def connection(n, app, host=None):
    return {'start':f'{n:05}', 'metadata':{'type':'Tun','processPath':app,
            'network':'tcp','host':host or f'site-{n}','destinationPort':'443','sourcePort':'321'}}


class TunActivityTests(unittest.TestCase):
    def test_both_groups_keep_their_own_twenty_across_samples(self):
        history={}
        apps=[connection(i,'ssh.exe') for i in range(25)]
        core=[connection(i,r'C:\proxy\XRAY.EXE') for i in range(25,325)]
        rows,counts=tun_activity.latest(history,apps+core)
        self.assertEqual(counts,{'其他应用':25,'Xray':300})
        self.assertEqual([r[2] for r in rows['其他应用']],[f'site-{i}' for i in range(24,4,-1)])
        self.assertEqual([r[2] for r in rows['Xray']],[f'site-{i}' for i in range(324,304,-1)])
        next_rows,_=tun_activity.latest(history,[connection(325,'xray.exe','site-324')])
        self.assertEqual(len(history),40)
        self.assertEqual(next_rows['其他应用'],rows['其他应用'])
        self.assertEqual(next_rows['Xray'][0][0],'00325')

    def test_only_the_identified_xray_executable_is_separated(self):
        with patch.object(tun_activity,'socket_owners',return_value={('tcp',321):{5}}), \
                patch.object(tun_activity,'process_name',return_value='xray.exe'):
            rows,_=tun_activity.latest({},[connection(1,''),connection(2,'my-xray.exe')])
        self.assertEqual([r[1] for r in rows['Xray']],['xray.exe'])
        self.assertEqual([r[1] for r in rows['其他应用']],['my-xray.exe'])
