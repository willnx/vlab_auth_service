# -*- coding: UTF-8 -*-
"""
Suite(s) of tests for the generate_token.py module
"""
import time
import unittest

import jwt

from vlab_auth_service.lib import const
from vlab_auth_service.lib import generate_token


class TestGenerateToken(unittest.TestCase):
    """Test suite for the generate_token.py module"""

    def setUp(self):
        """Runs before each test case"""
        self.username = 'pat'
        self.version = 1
        self.memberOf = []

    def test_basic_usage(self):
        """Calling generate_token function returns a JSON Web Token"""
        token = generate_token.generate_token(username=self.username,
                                              version=self.version,
                                              memberOf=self.memberOf,
                                              issued_at_timestamp=time.time())
        self.assertTrue(token is not None)

    def test_return_type(self):
        """Return type for generate_token function is Bytes"""
        token = generate_token.generate_token(username=self.username,
                                              version=self.version,
                                              memberOf=self.memberOf,
                                              issued_at_timestamp=time.time())
        self.assertTrue(isinstance(token, bytes))

    def test_token_content_keys(self):
        """The JSON Web Token contains all expected data"""
        time_stamp = time.time()
        token = generate_token.generate_token(username=self.username,
                                              version=self.version,
                                              memberOf=self.memberOf,
                                              issued_at_timestamp=time_stamp)
        token_data = jwt.decode(token, const.AUTH_TOKEN_SECRET, algorithms=const.AUTH_TOKEN_ALGORITHM)
        expected = {'memberOf' : [],
                    'username' : 'pat',
                    'version' : 1,
                    'iat' : time_stamp,
                    'exp' : time_stamp + const.AUTH_TOKEN_TIMEOUT,
                    'iss' : 'https://localhost'}

        self.assertEqual(token_data, expected)


class TestGenerateV2Token(unittest.TestCase):
    """Test suite for the generate_v2_token function"""

    def setUp(self):
        """Runs before each test case"""
        self.username = 'alice'
        self.version = 2
        self.memberOf = []

    def test_basic_usage(self):
        """Calling ``generate_v2_token`` returns a JWT"""
        token = generate_token.generate_v2_token(username=self.username,
                                                 version=self.version,
                                                 client_ip='127.0.0.1',
                                                 issued_at_timestamp=time.time())
        self.assertTrue(token is not None)

    def test_return_type(self):
        """Return type for generate_v2_token function is Bytes"""
        token = generate_token.generate_v2_token(username=self.username,
                                                 version=self.version,
                                                 client_ip='127.0.0.1',
                                                 issued_at_timestamp=time.time())

        self.assertTrue(isinstance(token, bytes))

    def test_token_content_keys(self):
        """The JSON Web Token contains all expected data"""
        time_stamp = time.time()
        token = generate_token.generate_v2_token(username=self.username,
                                                 version=self.version,
                                                 client_ip='127.0.0.1',
                                                 issued_at_timestamp=time_stamp)
        token_data = jwt.decode(token, const.AUTH_TOKEN_SECRET, algorithms=const.AUTH_TOKEN_ALGORITHM)
        expected = {'client_ip' : '127.0.0.1',
                    'username' : 'alice',
                    'version' : 2,
                    'iat' : time_stamp,
                    'exp' : time_stamp + const.AUTH_TOKEN_TIMEOUT,
                    'iss' : 'https://localhost'}

        self.assertEqual(token_data, expected)


if __name__ == '__main__':
    unittest.main()
