import unittest
import flow_log_parser as parser
from pathlib import Path


class TestGenProtocolMappings(unittest.TestCase):
    def setUp(self):
        self.mappings = parser.gen_protocol_mappings()

    def test_udp(self):
        self.assertTrue("17" in self.mappings)
        self.assertEqual(self.mappings["17"], "udp")

    def test_tcp(self):
        self.assertTrue("6" in self.mappings)
        self.assertEqual(self.mappings["6"], "tcp")

    def test_icmp(self):
        self.assertTrue("1" in self.mappings)
        self.assertEqual(self.mappings["1"], "icmp")


class TestParseLookup(unittest.TestCase):
    def test_empty(self):
        path = Path("test_inputs/empty.txt")
        self.assertEqual(parser.parse_lookup(path), {})

    def test_invalid_path(self):
        path = Path("test_inputs/asdopfiuqwepo.txt")
        self.assertRaises(FileNotFoundError, parser.parse_lookup, path)

    def test_sample(self):
        path = Path("test_inputs/sample_lookup.txt")
        self.assertEqual(parser.parse_lookup(path), {
            "25,tcp": "sv_P1",
            "68,udp": "sv_P2",
            "23,tcp": "sv_P1",
            "31,udp": "SV_P3",
            "443,tcp": "sv_P2",
            "22,tcp": "sv_P4",
            "3389,tcp": "sv_P5",
            "0,icmp": "sv_P5",
            "110,tcp": "email",
            "993,tcp": "email",
            "143,tcp": "email"
        })

    def test_invalid_lookup(self):
        path = Path("test_inputs/invalid_lookup.txt")
        self.assertEqual(parser.parse_lookup(path), {
            "25,tcp": "sv_P1",
            "443,tcp": "sv_P2",
            "22,tcp": "sv_P4",
            "3389,tcp": "sv_P5",
            "0,icmp": "sv_P5",
            "110,tcp": "email",
            "993,tcp": "email",
            "143,tcp": "email"
        })

    def test_single_lookup(self):
        path = Path("test_inputs/single_lookup.txt")
        self.assertEqual(parser.parse_lookup(path), {"31,udp": "SV_P3"})


class TestParseLog(unittest.TestCase):
    def setUp(self):
        path = Path("test_inputs/sample_lookup.txt")
        self.lookup = parser.parse_lookup(path)

    def test_empty(self):
        path = Path("test_inputs/empty.txt")
        tag_counts, port_protocol_counts = parser.parse_log(path, self.lookup)
        self.assertEqual(len(tag_counts), 0)
        self.assertEqual(len(port_protocol_counts), 0)

    def test_invalid_path(self):
        path = Path("test_inputs/alkdjf.txt")
        self.assertRaises(FileNotFoundError, parser.parse_log, path, self.lookup)

    def test_sample(self):
        path = Path("test_inputs/sample_log.txt")
        tag_counts, port_protocol_counts = parser.parse_log(path, self.lookup)
        self.assertEqual(tag_counts, {
            "sv_P2": 1,
            "sv_P1": 1,
            "email": 3,
            "Untagged": 7
        })
        self.assertEqual(port_protocol_counts, {
            "49153,tcp": 1,
            "49155,tcp": 1,
            "49156,tcp": 1,
            "49157,tcp": 1,
            "49158,tcp": 1,
            "80,tcp": 1,
            "1024,tcp": 1,
            "443,tcp": 1,
            "25,tcp": 1,
            "110,tcp": 1,
            "993,tcp": 1,
            "143,tcp": 1
        })

    def test_invalid_log(self):
        path = Path("test_inputs/invalid_log.txt")
        tag_counts, port_protocol_counts = parser.parse_log(path, self.lookup)
        self.assertEqual(tag_counts, {
            "sv_P1": 1,
            "email": 2,
            "Untagged": 4
        })
        self.assertEqual(port_protocol_counts, {
            "49156,tcp": 1,
            "49157,tcp": 1,
            "49158,tcp": 1,
            "1024,tcp": 1,
            "25,tcp": 1,
            "110,tcp": 1,
            "143,tcp": 1
        })

    def test_single_log(self):
        path = Path("test_inputs/single_log.txt")
        tag_counts, port_protocol_counts = parser.parse_log(path, self.lookup)
        self.assertEqual(tag_counts, {"email": 1})
        self.assertEqual(port_protocol_counts, {"993,tcp": 1})

    def test_duplicate_log(self):
        path = Path("test_inputs/duplicate_log.txt")
        tag_counts, port_protocol_counts = parser.parse_log(path, self.lookup)
        self.assertEqual(tag_counts, {"sv_P1": 3, "email": 4})
        self.assertEqual(port_protocol_counts, {"25,tcp": 3, "143,tcp": 4})


if __name__ == "__main__":
    unittest.main()
