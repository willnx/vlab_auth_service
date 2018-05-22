# -*- coding: UTF-8 -*-
"""
This module enables other services to consume the the JSON Web Tokens in vLab.
"""
import ujson
from flask_classy import request
from vlab_api_common import BaseView, get_logger

from vlab_auth_service.lib import const

logger = get_logger(__name__, loglevel=const.AUTH_LOG_LEVEL)


class KeyView(BaseView):
    """API end point for obtaining the public key, used to decode the JWT tokens"""
    route_base = '/api/1/auth/key'

    def get(self):
        """Obtain the Public RSA key to verify JWT signature"""
        resp = {}
        resp['format'] = const.AUTH_TOKEN_KEY_FORMAT
        resp['key'] = const.AUTH_TOKEN_PUB_KEY
        resp['algorithm'] = const.AUTH_TOKEN_ALGORITHM
        return ujson.dumps({'content' : resp}), 200
