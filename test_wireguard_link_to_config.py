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
parse_batch_links = wg_module.parse_batch_links
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

    def test_url_encoded_and_user_link(self):
        link = "wireguard://KNWhFayxBFdFwiqeUZPXP3UatGznky3DnC0UNmRDZHE%3D@tgc8337mar.adidasm10.ir:51860/?publickey=uTQ0YkFiu6G7WdLlwcyyFOw7Nyv4KQLdvrhQIm7Cl2Q%3D&address=100.80.2.138%2F32&allowedips=0.0.0.0%2F0%2C%3A%3A%2F0&dns=1.1.1.1%2C1.0.0.1#WGTorkey"
        res = parse_wireguard_link(link)

        self.assertEqual(res["name"], "WGTorkey")
        self.assertEqual(res["private_key"], "KNWhFayxBFdFwiqeUZPXP3UatGznky3DnC0UNmRDZHE=")
        self.assertEqual(res["public_key"], "uTQ0YkFiu6G7WdLlwcyyFOw7Nyv4KQLdvrhQIm7Cl2Q=")
        self.assertEqual(res["endpoint"], "tgc8337mar.adidasm10.ir:51860")
        self.assertEqual(res["address"], "100.80.2.138/32")
        self.assertEqual(res["dns"], "1.1.1.1,1.0.0.1")
        self.assertEqual(res["allowed_ips"], "0.0.0.0/0,::/0")

    def test_special_chars_in_base64_keys(self):
        link = "wireguard://abc+123/xyz=@host.domain:51820?publickey=pub+key/123=&presharedkey=psk+key/456="
        res = parse_wireguard_link(link)

        self.assertEqual(res["private_key"], "abc+123/xyz=")
        self.assertEqual(res["public_key"], "pub+key/123=")
        self.assertEqual(res["preshared_key"], "psk+key/456=")

    def test_parse_batch_links(self):
        content = """
        # Batch test
        wireguard://key1=@1.1.1.1:51820?publickey=pub1#Server1
        // Second comment
        wg://key2=@2.2.2.2:51820?publickey=pub2#Server2
        invalid line to ignore
        """
        configs, errors = parse_batch_links(content)
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(configs), 2)
        self.assertEqual(configs[0]["name"], "Server1")
        self.assertEqual(configs[1]["name"], "Server2")

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
