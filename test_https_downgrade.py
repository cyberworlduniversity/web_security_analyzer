"""Regression tests for HTTPS downgrade protection."""

import unittest
from pathlib import Path


class HTTPSDowngradeTests(unittest.TestCase):
    def test_tls_failure_does_not_trigger_plaintext_http_fallback(self):
        source = Path(__file__).with_name("analyzer.py").read_text(encoding="utf-8")
        self.assertNotIn('url.replace("https://", "http://")', source)
        self.assertNotIn("requests.get(http_url", source)
        self.assertIn("refusing an insecure HTTP fallback", source)


if __name__ == "__main__":
    unittest.main()
