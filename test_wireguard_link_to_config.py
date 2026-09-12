#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

script_path = Path(__file__).parent / "wireguard-link-to-config.py"
spec = importlib.util.spec_from_file_location("wireguard_link_to_config", script_path)
wg_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wg_module)

sanitize_config_name = wg_module.sanitize_config_name
parse_wireguard_link = wg_module.parse_wireguard_link
generate_conf_content = wg_module.generate_conf_content


class TestWireGuardLinkToConfig(unittest.TestCase):
    def test_standard_link_without_mtu(self):
        link = "wireguard://cGVyc29uYWxfcHJpdmF0ZV9rZXk=@198.51.100.1:51820?publickey=cGVyc29uYWxfcHVibGljX2tleQ==&address=10.0.0.5/32&dns=8.8.8.8&allowed_ips=0.0.0.0/0#MyServer"
        res = parse_wireguard_link(link)

        self.assertEqual(res["name"], "MyServer")
        self.assertEqual(res["private_key"], "cGVyc29uYWxfcHJpdmF0ZV9rZXk=")
        self.assertEqual(res["public_key"], "cGVyc29uYWxfcHVibGljX2tleQ==")
        self.assertEqual(res["endpoint"], "198.51.100.1:51820")
        self.assertEqual(res["address"], "10.0.0.5/32")
        self.assertEqual(res["dns"], "8.8.8.8")
        self.assertEqual(res["allowed_ips"], "0.0.0.0/0")
        self.assertEqual(res["mtu"], "")

        conf = generate_conf_content(res)
        self.assertNotIn("MTU", conf)
        self.assertIn("PrivateKey = cGVyc29uYWxfcHJpdmF0ZV9rZXk=", conf)
        self.assertIn("Endpoint = 198.51.100.1:51820", conf)

    def test_link_with_mtu_and_keepalive(self):
        link = "wg://test_priv@wg.example.com:51820?publickey=test_pub&mtu=1420&keepalive=25&presharedkey=psk123#TestNode"
        res = parse_wireguard_link(link)

        self.assertEqual(res["name"], "TestNode")
        self.assertEqual(res["mtu"], "1420")
        self.assertEqual(res["persistent_keepalive"], "25")
        self.assertEqual(res["preshared_key"], "psk123")

        conf = generate_conf_content(res)
        self.assertIn("MTU = 1420", conf)
        self.assertIn("PersistentKeepalive = 25", conf)
        self.assertIn("PresharedKey = psk123", conf)

    def test_sanitize_config_name(self):
        self.assertEqual(sanitize_config_name("Server.conf"), "Server")
        self.assertEqual(sanitize_config_name("  TORK  "), "TORK")
        with self.assertRaises(ValueError):
            sanitize_config_name("../bad")
        with self.assertRaises(ValueError):
            sanitize_config_name("bad/slash")
        with self.assertRaises(ValueError):
            sanitize_config_name("")


if __name__ == "__main__":
    unittest.main()
