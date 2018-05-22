# -*- coding: UTF-8 -*-
"""
Enables Health checks for the Auth service

.. note::
    Any and all healthchecks end points should verify that the entire service
    is up and available, not just the RESTful end point.

"""
from time import time
import pkg_resources

import ldap3
from ldap3.core.exceptions import LDAPException
import ujson
from redis import StrictRedis, RedisError
from flask_classy import FlaskView, Response

from vlab_auth_service.lib import const


class HealthView(FlaskView):
    """
    Simple end point to test if the service is alive
    """
    route_base = '/api/1/auth/healthcheck'
    trailing_slash = False

    def get(self):
        """End point for health checks"""
        resp = {'redis' : {}, 'auth_api' : {}, 'ldap' : {}}
        status = 200
        redis_stime = time()
        try:
            r = StrictRedis(host=const.AUTH_REDIS_HOSTNAME, port=const.AUTH_REDIS_PORT)
            r.config_get('*')
        except RedisError as doh:
            resp['redis']['msg'] = '%s' % doh
            status = 500
        else:
            resp['redis']['msg'] = 'OK'
        resp['redis']['latency'] = time() - redis_stime

        ldap_stime = time()
        try:
            server = ldap3.Server(const.AUTH_LDAP_URL, get_info=None)
            conn = ldap3.Connection(server, auto_bind=True)
        except LDAPException as derp:
            resp['ldap']['msg'] = '%s' % derp
            status = 500
        else:
            resp['ldap']['msg'] = 'OK'
            conn.unbind()
        resp['ldap']['latency'] = time() - ldap_stime

        resp['auth_api']['version'] = pkg_resources.get_distribution('vlab-auth-service').version
        response = Response(ujson.dumps(resp))
        response.status_code = status
        response.headers['Content-Type'] = 'application/json'
        return response
