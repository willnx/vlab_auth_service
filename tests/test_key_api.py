# -*- coding: UTF-8 -*-
"""
Test suite(s) for the Key API
"""
import unittest
from unittest.mock import patch, MagicMock

import ujson

import vlab_auth_service.app as auth_app
from vlab_auth_service.lib.views import key


class TestKeyView(unittest.TestCase):
    """Test cases for KeyView -> /api/1/auth/key API end point"""

    def setUp(self):
        auth_app.app.config['TESTING'] = True
        self.app = auth_app.app.test_client()

    def test_get_status_code(self):
        """GET on /api/1/auth/key returns a 200 on success"""
        resp = self.app.get('/api/1/auth/key')

        self.assertEqual(resp.status_code, 200)

    def test_get_body_content(self):
        """GET on /api/1/auth/key return expected body content"""
        resp = self.app.get('/api/1/auth/key')
        data = ujson.loads(resp.data)
        expected = {'content': {'format': 'pem', 'key': 'testing', 'algorithm': 'HS256'}, 'error': None, 'params': {}}

        self.assertEqual(data, expected)


if __name__ == '__main__':
    unittest.main()
