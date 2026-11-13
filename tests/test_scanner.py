import unittest

from scanner import _split_ip_port, assess_connection_security


class AddressParsingTests(unittest.TestCase):
    def test_splits_ipv4_address_and_port(self):
        self.assertEqual(_split_ip_port("127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_splits_bracketed_ipv6_address_and_port(self):
        self.assertEqual(_split_ip_port("[::1]:8080"), ("::1", 8080))

    def test_returns_zero_for_missing_port(self):
        self.assertEqual(_split_ip_port("localhost"), ("localhost", 0))


class ConnectionAssessmentTests(unittest.TestCase):
    def test_common_https_traffic_is_safe(self):
        result = assess_connection_security(
            "TCP", 51000, "203.0.113.10", 443, "ESTABLISHED", "browser.exe"
        )
        self.assertEqual(result["level"], "SAFE")

    def test_high_risk_listener_is_flagged_for_review(self):
        result = assess_connection_security(
            "TCP", 445, "0.0.0.0", 0, "LISTENING", "service.exe"
        )
        self.assertEqual(result["level"], "SUSPICIOUS")

    def test_uncommon_external_port_is_flagged_for_unknown_process(self):
        result = assess_connection_security(
            "TCP", 51000, "203.0.113.10", 8888, "ESTABLISHED", "unknown.exe"
        )
        self.assertEqual(result["level"], "SUSPICIOUS")


if __name__ == "__main__":
    unittest.main()
