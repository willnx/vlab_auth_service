# -*- coding: UTF-8 -*-
"""
Test suite(s) for the Healthcheck API
"""
import unittest
from unittest.mock import patch

import ujson
from redis import RedisError
from ldap3.core.exceptions import LDAPException, LDAPBindError

import vlab_auth_service.app as auth_app
from vlab_auth_service.lib.views import healthcheck

class HealthCheckTest(unittest.TestCase):
    """A set of test cases for '/api/1/auth/healthcheck'"""

    def setUp(self):
        auth_app.app.config['TESTING'] = True
        self.app = auth_app.app.test_client()

    @patch.object(healthcheck, 'StrictRedis')
    @patch.object(healthcheck, 'ldap3')
    def test_healthcheck_basic(self, fake_ldap3, fake_strict_redis):
        """The healthcheck module works under the most basic use case"""
        resp = self.app.get('/api/1/auth/healthcheck')
        expected = 200

        self.assertEqual(resp.status_code, expected)

    @patch.object(healthcheck, 'StrictRedis')
    @patch.object(healthcheck, 'ldap3')
    def test_healthcheck_ldap_error(self, fake_ldap3, fake_strict_redis):
        """Catching an LDAPBindError is how we determine if the LDAP server is offline"""
        fake_ldap3.Connection.side_effect = LDAPException('testing')
        resp = self.app.get('/api/1/auth/healthcheck')
        expected = 500

        self.assertEqual(resp.status_code, expected)


    @patch.object(healthcheck, 'StrictRedis')
    @patch.object(healthcheck, 'ldap3')
    def test_healthcheck_redis_error(self, fake_ldap3, fake_strict_redis):
        """Catching an RedisError is how we determine if the Redis server is offline"""
        fake_strict_redis.side_effect = RedisError('testing')
        resp = self.app.get('/api/1/auth/healthcheck')
        expected = 500

        self.assertEqual(resp.status_code, expected)


if __name__ == '__main__':
    unittest.main()
