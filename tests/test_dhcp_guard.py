import ctypes as c
import sys
import unittest
import uuid
from unittest.mock import patch


@unittest.skipUnless(sys.platform == "win32", "Windows Filtering Platform")
class DhcpGuardTests(unittest.TestCase):
    def test_dhcp_permit_is_scoped_to_service_interface_and_udp_ports(self):
        import guard_live as guard

        observed = []

        def inspect(handle, sublayer, layer, label, action, weight, conditions):
            fields = {str(uuid.UUID(bytes_le=bytes(item.key))): item for item in conditions}
            self.assertEqual(len(fields), 6)
            self.assertTrue(all(item.match == 0 for item in conditions))
            self.assertEqual(action, guard.g["PERMIT"])
            app = guard.g["Blob"].from_address(fields[guard.g["APP"]].value.data.pointer)
            path = c.string_at(app.data, app.size).decode("utf-16le").rstrip("\0").lower()
            self.assertTrue(path.endswith(r"\windows\system32\svchost.exe"))
            token = fields["af043a0a-b34d-4f86-979c-c90371af6e66"].value
            self.assertEqual(token.type, 14)
            descriptor = guard.g["Blob"].from_address(token.data.pointer)
            text = c.c_wchar_p()
            self.assertTrue(c.windll.advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                c.c_void_p(descriptor.data), 1, 4, c.byref(text), None))
            try:
                self.assertEqual(text.value, "D:(A;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)")
            finally:
                c.windll.kernel32.LocalFree(c.cast(text, c.c_void_p))
            interface = fields["4cd62a49-59c3-4969-b7f3-bda5d32890a4"].value.data.pointer
            self.assertEqual(c.c_uint64.from_address(interface).value, 123)
            self.assertEqual(fields["3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"].value.data.number, 17)
            observed.append((layer, fields["0c1ba1af-5765-453f-af22-a8f791ac775b"].value.data.number,
                             fields["c35a604d-d22b-4e1a-91b4-68f674ee674b"].value.data.number))

        with patch.dict(guard.g, add_filter=inspect):
            guard.add_dhcp_filters(None, None, ())
            guard.add_dhcp_filters(None, None, (123,))
        self.assertEqual(observed, [(guard.g["LAYERS"][0], 68, 67), (guard.g["LAYERS"][1], 546, 547)])
