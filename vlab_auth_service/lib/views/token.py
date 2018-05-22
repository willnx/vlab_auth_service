# -*- coding: UTF-8 -*-
"""
This module defines the API for working with auth tokens in vLab.
"""
import time

import jwt
import ujson
import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
from redis import StrictRedis, RedisError
from flask import url_for
from flask_classy import request, Response
from vlab_api_common import BaseView, describe, get_logger
from jsonschema import validate, ValidationError

from vlab_auth_service.lib import const
from vlab_auth_service.lib.generate_token import generate_token

logger = get_logger(__name__, loglevel=const.AUTH_LOG_LEVEL)


class TokenView(BaseView):
    """API end point for obtaining an auth token"""
    route_base = '/api/1/auth/token'
    version = 1
    GET_ARGS_SCHEMA = {"$schema": "http://json-schema.org/draft-04/schema#",
    	               "type": "object",
                       "properties": {
                          "token" : {
                          "type" : "string",
                          "description" : "Check if the token has been deleted"
                          }
                       }
                      }
    DELETE_SCHEMA = {"$schema": "http://json-schema.org/draft-04/schema#",
    	             "type": "object",
                	 "properties": {
                        "token" : {
                            "type" : "string",
                            "description" : "Delete the token"
                        }
                     },
                     "required": [
                        "token"
                     ]
                    }
    POST_SCHEMA = { "$schema": "http://json-schema.org/draft-04/schema#",
    	            "type": "object",
                	"properties": {
                		"username": {
                			"type": "string",
                			"description": "The username to authenticate"
                		},
                		"password": {
                			"type": "string",
                			"description": "The password for the user"
                		}
                	},
                	"required": [
                		"username",
                		"password"
                	]
                }

    @describe(get_args=GET_ARGS_SCHEMA, delete=DELETE_SCHEMA, post=POST_SCHEMA)
    def get(self):
        """Check if a token has been deleted"""
        resp = {'user' : 'unknown'}
        token = request.args.get('token', default=None)
        if token is None:
            resp['error'] = "Must supply the token parameter"
            return ujson.dumps(resp), 400
        try:
            redis_server = StrictRedis(host=const.AUTH_REDIS_HOSTNAME, port=const.AUTH_REDIS_PORT)
            if redis_server.get(token):
                status = 200
            else:
                status = 404
        except RedisError as doh:
            logger.exception(doh)
            status = 503
        return ujson.dumps(resp), status

    def post(self, *args, **kwargs):
        """Obtain an auth token"""
        resp = {"user" : "unknown"}
        body = request.get_json()
        if not _input_valid(body=body, schema=self.POST_SCHEMA):
            resp['error'] = 'Invalid HTTP body supplied'
            return ujson.dumps(resp), 400
        else:
            resp['user'] = body['username']

        conn, status = _bind_ldap(body['username'], body['password'])
        if not conn:
            if status == 401:
                resp['error'] = 'Invalid username or password'
            elif status == 503:
                resp['error'] = 'Unable to connect to LDAP server'
            return ujson.dumps(resp), status

        memberOf, error = _user_ok(conn, body['username'])
        conn.unbind()
        if not memberOf:
            status = 500
            resp['error'] = error
            resp['content'] = {'token' : ''}
        elif error:
            resp['error'] = error
            resp['content'] = {'token' : ''}
            status = 403
        else:
            token = generate_token(username=body['username'],
                                   version=self.version,
                                   memberOf=memberOf,
                                   issued_at_timestamp=time.time())
            if _added_token_to_redis(token, body['username']):
                resp['content'] = {'token' : token}
            else:
                resp['error'] = 'Unable to persist token record'
                resp['content'] = {'token' : ''}
                status = 503
        return ujson.dumps(resp), status

    def delete(self, *args, **kwargs):
        """Delete a token"""
        resp = {'user' : 'unknown'}
        status = 200
        body = request.get_json()
        if not _input_valid(body=body, schema=self.DELETE_SCHEMA):
            resp['error'] = 'Invalid HTTP body supplied'
            status = 400
        else:
            try:
                redis_server = StrictRedis(host=const.AUTH_REDIS_HOSTNAME, port=const.AUTH_REDIS_PORT)
                if redis_server.delete(body['token']):
                    logger.info("Token delete: %s" % body['token'])
                else:
                    logger.info("Attempt to delete non-existing token %s" % body['token'])
            except RedisError as doh:
                logger.exception(doh)
                resp['error'] = "unable to delete token"
                status = 503
        return ujson.dumps(resp), status


def _added_token_to_redis(token, username, log=logger):
    """Add the token to Redis, so users can delete them if needed

    :Returns: Boolean

    :param token: The JWT created for the supplied user
    :type token: String

    :param username: The name of the user who owns the token
    :type username: String

    :param log: A logging object
    :param log: logging.Logger
    """
    ok = True
    try:
        redis_server = StrictRedis(host=const.AUTH_REDIS_HOSTNAME, port=const.AUTH_REDIS_PORT)
        redis_server.set(token, username, ex=const.AUTH_TOKEN_TIMEOUT) # Auto expire token in Redis
    except RedisError as doh:
        log.exception(doh)
        ok = False
    return ok


def _user_ok(ldap_conn, username, log=logger):
    """Ensure the user's account isn't locked or disabled. If the account is
    valid, return their group membership.

    :Returns: Tuple (memberOf, error)

    :param ldap_conn: A bound connection to the LDAP server
    :type ldap_conn: ldap3.core.connection.Connection

    :param username: The user to lookup group membership for
    :type username: String

    :param log: A logging object
    :param log: logging.Logger
    """
    search_filter = '(&(objectclass=User)(uid=%s))' % username
    ldap_conn.search(search_base=const.AUTH_SEARCH_BASE,
                     search_filter=search_filter,
                     attributes=['memberOf', 'userAccountControl'])
    if len(ldap_conn.entries) != 1:
        err = 'Found {} users by name {}, '.format(len(ldap_conn.entries), username)
        err += 'unable to determine group memebership'
        log.error(err)
        memberOf = []
        error = 'Multiple accounts found for %s' % username
    else:
        ldap_user = ldap_conn.entries[0]
        memberOf = [x for x in ldap_user.memberOf]
        disabled = ldap_user.userAccountControl.value >> 1 & 1 # bit shift to the 2nd bit, and test if it's 1 or 0
        locked = ldap_user.userAccountControl.value >> 4 & 1
        if locked:
            error = "Account locked"
        elif disabled:
            error = "Account disabled"
        else:
            error = ''
    return memberOf, error


def _bind_ldap(username, password, log=logger):
    """Bind to the configured LDAP server.

    If the bind is successful, the connection object is returned. If the bind
    was unsuccessful, the connection object will be None. The status returned
    is intended to be the HTTP status code.

    :Returns: Tuple (ldap3.core.connection.Connection, status)

    :param username: The SamAccountName (i.e. no domain prefix)
    :type username: String

    :param password: The user's password
    :type password: String

    :param log: A logging object
    :param log: logging.Logger
    """
    conn = None
    status = 200
    try:
        full_username = "{0}@{1}".format(username, const.AUTH_BASE)
        server = ldap3.Server(const.AUTH_LDAP_URL)
        conn = ldap3.Connection(server, full_username, password, auto_bind=True)
    except LDAPBindError:
        log.error("Login attempt failed for {}".format(username))
        time.sleep(const.FAILED_LOGIN_PAUSE)
        status = 401
    except LDAPSocketOpenError:
        log.error('LDAP Down for {0}'.format(const.AUTH_LDAP_URL))
        status = 503
    return conn, status


def _input_valid(body, schema):
    """Ensures body content was sent, and that it aligns with the define schema

    :Returns: Boolean

    :param body: The body content sent in the HTTP request
    :type body: String

    :param schema: The JSON Schema the body content must adhere to
    :type Schema: PyObject
    """
    ok = True
    if not body:
        logger.error('No content body supplied')
        ok = False
    try:
        validate(body, schema)
    except ValidationError:
        logger.error("Validation failed:\nBody: {}\nSchema:{}".format(body, schema))
        ok = False
    return ok
