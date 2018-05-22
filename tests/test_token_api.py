# -*- coding: UTF-8 -*-
"""
Test suite(s) for the Token API
"""
import unittest
from unittest.mock import patch, MagicMock

import ujson
import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
from redis import RedisError
from jsonschema import Draft4Validator

import vlab_auth_service.app as auth_app
from vlab_auth_service.lib.views import token


class ApiTester(unittest.TestCase):
    """
    Common setup logic for testing the API
    """
    def setUp(self):
        auth_app.app.config['TESTING'] = True
        self.app = auth_app.app.test_client()


class AuthApiTokenGet(ApiTester):
    """
    A set of test cases for GET on '/api/1/auth/token'
    """
    def test_get_describe(self):
        """?describe=trues returns JSON"""
        resp = self.app.get('/api/1/auth/token?describe=true')
        data = resp.get_json()

        self.assertEqual(resp.headers['content-type'], 'application/json')

    def test_get_no_token(self):
        """GET on /api/1/auth/token without param 'token' returns 400"""
        resp = self.app.get('/api/1/auth/token')

        self.assertEqual(resp.status_code, 400)

    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_get_redis_down(self, fake_logger, fake_strict_redis):
        """GET on /api/1/auth/token returns 503 when RedisError is encounted"""
        fake_strict_redis.side_effect = RedisError('testing')

        resp = self.app.get('/api/1/auth/token?token=asdfasdfasdfasdfsdf')

        self.assertEqual(resp.status_code, 503)

    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_get_token_deleted(self, fake_logger, fake_strict_redis):
        """GET on /api/1/auth/token returns 404 when the token has been deleted"""
        fake_strict_redis.return_value.get.return_value = False
        resp = self.app.get('/api/1/auth/token?token=asdfasdfasdfasdfsdf')

        self.assertEqual(resp.status_code, 404)

    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_get_ok(self, fake_logger, fake_strict_redis):
        """GET on /api/1/auth/token returns 200 when the token is valid"""
        resp = self.app.get('/api/1/auth/token?token=asdfasdfasdfasdfsdf')

        self.assertEqual(resp.status_code, 200)


class AuthApiTokenPost(ApiTester):
    """
    A set of test cases for POST on '/api/1/auth/token'
    """
    @patch.object(token, 'logger')
    def test_post_bad_body(self, fake_logger):
        """POST on /api/1/auth/token returns 400 when no body content is supplied"""
        resp = self.app.post('/api/1/auth/token',
                             content_type='application/json',
                             data=ujson.dumps({}))

        self.assertEqual(resp.status_code, 400)

    @patch.object(token, 'logger')
    def test_post_no_body(self, fake_logger):
        """POST on /api/1/auth/token returns 400 when no body content is supplied"""
        resp = self.app.post('/api/1/auth/token')

        self.assertEqual(resp.status_code, 400)

    @patch.object(token, '_bind_ldap')
    @patch.object(token, '_user_ok')
    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_post_bad_creds(self, fake_logger, fake_strict_redis, fake_user_ok, fake_bind_ldap):
        """POST on /api/1/auth/token returns 401 when username/password is invalid"""
        fake_user_ok.return_value = ['some-group'], ''
        fake_bind_ldap.return_value = None, 401
        resp = self.app.post('/api/1/auth/token',
                             content_type='application/json',
                             data=ujson.dumps({'username' : 'bob', 'password' : 'IloveCats'}))

        self.assertEqual(resp.status_code, 401)

    @patch.object(token, '_bind_ldap')
    @patch.object(token, '_user_ok')
    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_post_ldap_down(self, fake_logger, fake_strict_redis, fake_user_ok, fake_bind_ldap):
        """POST on /api/1/auth/token returns 503 when the LDAP server is down"""
        fake_user_ok.return_value = ['some-group'], ''
        fake_bind_ldap.return_value = None, 503
        resp = self.app.post('/api/1/auth/token',
                             content_type='application/json',
                             data=ujson.dumps({'username' : 'bob', 'password' : 'IloveCats'}))

        self.assertEqual(resp.status_code, 503)

    @patch.object(token, '_bind_ldap')
    @patch.object(token, '_user_ok')
    @patch.object(token, '_added_token_to_redis')
    @patch.object(token, 'logger')
    def test_post_redis_down(self, fake_logger, fake_added_token_to_redis, fake_user_ok, fake_bind_ldap):
        """POST on /api/1/auth/token returns 503 when unable to store the token in Redis"""
        fake_user_ok.return_value = ['some-group'], ''
        fake_bind_ldap.return_value = MagicMock(), 200
        fake_added_token_to_redis.return_value = False
        resp = self.app.post('/api/1/auth/token',
                             content_type='application/json',
                             data=ujson.dumps({'username' : 'bob', 'password' : 'IloveCats'}))

        self.assertEqual(resp.status_code, 503)

    @patch.object(token, '_bind_ldap')
    @patch.object(token, '_user_ok')
    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_post_user_denied(self, fake_logger, fake_strict_redis, fake_user_ok, fake_bind_ldap):
        """POST on /api/1/auth/token returns 403 when the user is denied, but exists"""
        fake_user_ok.return_value = ['some-group'], 'Account Locked'
        fake_bind_ldap.return_value = MagicMock(), 200
        resp = self.app.post('/api/1/auth/token',
                             content_type='application/json',
                             data=ujson.dumps({'username' : 'bob', 'password' : 'IloveCats'}))

        self.assertEqual(resp.status_code, 403)

    @patch.object(token, '_bind_ldap')
    @patch.object(token, '_user_ok')
    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_post_no_memberOf(self, fake_logger, fake_strict_redis, fake_user_ok, fake_bind_ldap):
        """POST on /api/1/auth/token returns 500 if user group membership is empty"""
        fake_user_ok.return_value = [], 'Uanble to determine mebership'
        fake_bind_ldap.return_value = MagicMock(), 200
        resp = self.app.post('/api/1/auth/token',
                             content_type='application/json',
                             data=ujson.dumps({'username' : 'bob', 'password' : 'IloveCats'}))

        self.assertEqual(resp.status_code, 500)

    @patch.object(token, '_bind_ldap')
    @patch.object(token, '_user_ok')
    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_post_ok(self, fake_logger, fake_strict_redis, fake_user_ok, fake_bind_ldap):
        """POST on /api/1/auth/token returns 200 when a token is returned"""
        fake_user_ok.return_value = ['some-group'], ''
        fake_bind_ldap.return_value = MagicMock(), 200
        resp = self.app.post('/api/1/auth/token',
                             content_type='application/json',
                             data=ujson.dumps({'username' : 'bob', 'password' : 'IloveCats'}))

        self.assertEqual(resp.status_code, 200)


class AuthApiTokenDelete(ApiTester):
    """
    A set of test cases for POST on '/api/1/auth/token'
    """
    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_delete_no_body(self, fake_logger, fake_strict_redis):
        """DELETE on /api/1/auth/token returns 400 when there is no body content"""
        resp = self.app.delete('/api/1/auth/token')

        self.assertEqual(resp.status_code, 400)

    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_delete_bad_body(self, fake_logger, fake_strict_redis):
        """DELETE on /api/1/auth/token returns 400 when provided with invalid body content"""
        resp = self.app.delete('/api/1/auth/token',
                               content_type='application/json',
                               data=ujson.dumps({}))

        self.assertEqual(resp.status_code, 400)

    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_delete_redis_down(self, fake_logger, fake_strict_redis):
        """DELETE on /api/1/auth/token returns 503 when it cannot connect to Redis"""
        fake_strict_redis.side_effect = RedisError('testing')
        resp = self.app.delete('/api/1/auth/token',
                               content_type='application/json',
                               data=ujson.dumps({'token' : 'asdfasdf'}))

        self.assertEqual(resp.status_code, 503)


    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_delete_already_gone(self, fake_logger, fake_strict_redis):
        """DELETE on /api/1/auth/token returns 200 when the token is already gone from Redis"""
        fake_strict_redis.return_value.delete.return_value = False
        resp = self.app.delete('/api/1/auth/token',
                               content_type='application/json',
                               data=ujson.dumps({'token' : 'asdfasdf'}))

        self.assertEqual(resp.status_code, 200)

    @patch.object(token, 'StrictRedis')
    @patch.object(token, 'logger')
    def test_delete_ok(self, fake_logger, fake_strict_redis):
        """DELETE on /api/1/auth/token returns 200 when the token is removed from Redis"""
        resp = self.app.delete('/api/1/auth/token',
                               content_type='application/json',
                               data=ujson.dumps({'token' : 'asdfasdf'}))

        self.assertEqual(resp.status_code, 200)


class AuthApiTokenSchemas(unittest.TestCase):
    """
    A suite of tests for the API schemas used in /api/1/auth/token
    """

    def test_get_args_schema(self):
        """The schema we've defined for GET args on /api/1/auth/token is valid"""
        try:
            Draft4Validator.check_schema(token.TokenView.GET_ARGS_SCHEMA)
            schema_valid = True
        except RuntimeError:
            schema_valid = False

        self.assertTrue(schema_valid)

    def test_delete_schema(self):
        """The schema we've defined for DELETE on /api/1/auth/token is valid"""
        try:
            Draft4Validator.check_schema(token.TokenView.DELETE_SCHEMA)
            schema_valid = True
        except RuntimeError:
            schema_valid = False

        self.assertTrue(schema_valid)

    def test_post_schema(self):
        """The schema we've defined for POST on /api/1/auth/token is valid"""
        try:
            Draft4Validator.check_schema(token.TokenView.POST_SCHEMA)
            schema_valid = True
        except RuntimeError:
            schema_valid = False

        self.assertTrue(schema_valid)


class TestTokenHelpers(unittest.TestCase):
    """A suite of tests for the internal helper functions for the token module"""
    @patch.object(token, 'StrictRedis')
    def test_added_token_to_redis_down(self, fake_StrictRedis):
        """_added_token_to_redis returns True when Redis adds the token"""
        result = token._added_token_to_redis(token='asdf', username='bob', log=MagicMock())

        self.assertTrue(result)

    @patch.object(token, 'StrictRedis')
    def test_added_token_to_redis_down(self, fake_StrictRedis):
        """_added_token_to_redis returns False when RedisError is raised"""
        fake_StrictRedis.side_effect = RedisError('testing')
        result = token._added_token_to_redis(token='asdf', username='bob', log=MagicMock())

        self.assertFalse(result)

    def test_user_ok_many_users(self):
        """_user_ok returns an error if multiple users are found"""
        fake_conn = MagicMock()
        fake_conn.entries = ['bob', 'bob']

        memberOf, error = token._user_ok(ldap_conn=fake_conn, username='bob', log=MagicMock())
        expected_error = 'Multiple accounts found for bob'
        expected_memberOf = []

        self.assertEqual(error, expected_error)
        self.assertEqual(memberOf, expected_memberOf)

    def test_user_ok_locked(self):
        """_user_ok returns an error if the user's account is locked"""
        fake_conn = MagicMock()
        fake_user = MagicMock()
        fake_user.userAccountControl.value = 16
        fake_conn.entries = [fake_user]

        _, error = token._user_ok(ldap_conn=fake_conn, username='bob', log=MagicMock())
        expected_error = "Account locked"

        self.assertEqual(error, expected_error)

    def test_user_ok_disabled(self):
        """_user_ok returns an error if the user's account is disabled"""
        fake_conn = MagicMock()
        fake_user = MagicMock()
        fake_user.userAccountControl.value = 2
        fake_conn.entries = [fake_user]

        _, error = token._user_ok(ldap_conn=fake_conn, username='bob', log=MagicMock())
        expected_error = "Account disabled"

        self.assertEqual(error, expected_error)

    def test_user_ok(self):
        """_user_ok returns the list of group membership when everything is OK"""
        fake_conn = MagicMock()
        fake_user = MagicMock()
        fake_user.userAccountControl.value = 0
        fake_user.memberOf = ['some-group']
        fake_conn.entries = [fake_user]

        memberOf, err = token._user_ok(ldap_conn=fake_conn, username='bob', log=MagicMock())
        expected_memberOf = ['some-group']

        self.assertEqual(memberOf, expected_memberOf)
        self.assertEqual(err, '')

    @patch.object(token, 'ldap3')
    def test_bind_ldap_bad_creds(self, fake_ldap3):
        """_bind_ldap returns 401 when a invalid user creds are supplied"""
        fake_ldap3.Connection.side_effect = LDAPBindError("testing")

        _, status = token._bind_ldap('bob', 'iLoveCats', log=MagicMock())

        self.assertEqual(status, 401)

    @patch.object(token, 'ldap3')
    def test_bind_ldap_down(self, fake_ldap3):
        """_bind_ldap returns 503 when the LDAP server is down"""
        fake_ldap3.Connection.side_effect = LDAPSocketOpenError("testing")

        _, status = token._bind_ldap('bob', 'iLoveCats', log=MagicMock())

        self.assertEqual(status, 503)


if __name__ == '__main__':
    unittest.main()
