import os
import unittest
from unittest.mock import patch

from utils.link_checker import _validate_public_http_url


class URLSafetyTests(unittest.TestCase):
    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            _validate_public_http_url("file:///etc/passwd")

    def test_rejects_localhost(self):
        with self.assertRaises(ValueError):
            _validate_public_http_url("http://localhost/admin")

    def test_rejects_private_ip(self):
        with self.assertRaises(ValueError):
            _validate_public_http_url("http://127.0.0.1/")

    def test_rejects_url_credentials(self):
        with self.assertRaises(ValueError):
            _validate_public_http_url("https://user:pass@example.com/")

    @patch("utils.link_checker.socket.getaddrinfo")
    def test_rejects_hostname_resolving_to_private_ip(self, resolver):
        resolver.return_value = [(None, None, None, None, ("10.0.0.5", 443))]
        with self.assertRaises(ValueError):
            _validate_public_http_url("https://example.test/")


if __name__ == "__main__":
    unittest.main()
