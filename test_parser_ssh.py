import csv
import tempfile
import unittest
from pathlib import Path

from parser_ssh import convert, parse_line


class SSHParserTests(unittest.TestCase):
    def test_failed_password(self):
        line = "Nov 11 10:01:00 server sshd[100]: Failed password for invalid user admin from 203.0.113.10 port 12345 ssh2"
        self.assertEqual(parse_line(line, 2026), {
            "timestamp": "2026-11-11 10:01:00", "ip": "203.0.113.10", "status": "FAIL", "username": "admin"
        })

    def test_accepted_publickey(self):
        line = "Nov 11 10:01:00 server sshd-session[100]: Accepted publickey for bob from 192.0.2.40 port 12345 ssh2: ED25519 SHA256:EXAMPLE"
        self.assertEqual(parse_line(line, 2026)["status"], "SUCCESS")

    def test_ignores_unrelated_and_invalid_ip(self):
        line = "Nov 11 10:01:00 server sshd[100]: Invalid user bob from 192.0.2.40 port 12345"
        self.assertIsNone(parse_line(line, 2026))
        bad_ip = "Nov 11 10:01:00 server sshd[100]: Failed password for bob from not_an_ip port 12345 ssh2"
        self.assertIsNone(parse_line(bad_ip, 2026))

    def test_converts_without_overwriting_project_data(self):
        sample = Path(__file__).parent / "data" / "sample_ssh_auth.log"
        with tempfile.TemporaryDirectory() as tempdir:
            outfile = Path(tempdir) / "normalized.csv"
            summary = convert(sample, outfile, 2026)
            with outfile.open(encoding="utf-8", newline="") as file:
                rows = list(csv.DictReader(file))
        self.assertEqual(summary, {"convertidos": 8, "ignorados": 2})
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row["ip"] == "203.0.113.10" and row["status"] == "FAIL" for row in rows), 3)
        self.assertEqual(sum(row["ip"] == "198.51.100.24" and row["status"] == "FAIL" for row in rows), 3)
        self.assertEqual(sum(row["status"] == "SUCCESS" for row in rows), 2)


if __name__ == "__main__":
    unittest.main()
