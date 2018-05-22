# -*- coding: UTF-8 -*-
"""
All the things can override via Environment variables are keep in this one file.

.. note::
    Any and all values that *are* passwords must contain the string 'AUTH' in
    the name of the constant. This is how we avoid logging passwords.
"""
from os import environ
from collections import namedtuple, OrderedDict

try:
    with open('/etc/vlab/auth_server/private.key') as the_file:
        secret = the_file.read()
    with open('/etc/vlab/auth_server/public.key') as the_file:
        pub_key = the_file.read()
except OSError:
    # assume testing env
    secret = 'testing'
    pub_key = 'testing'

DEFINED = OrderedDict([
            ('AUTH_LOG_LEVEL', environ.get('AUTH_LOG_LEVEL', 'INFO')),
            ('AUTH_REDIS_HOSTNAME', environ.get('AUTH_REDIS_HOSTNAME', 'auth-redis')),
            ('AUTH_REDIS_PORT', environ.get('AUTH_REDIS_PORT', '6379')),
            ('AUTH_LDAP_URL', environ.get('AUTH_LDAP_URL', 'ldaps://localhost')),
            ('AUTH_BASE', environ.get('AUTH_BASE', 'localhost.local')),
            ('FAILED_LOGIN_PAUSE', 0.2), # Slow down any brute force login attempt
            ('AUTH_SEARCH_BASE', 'DC=localhost,DC=local'),
            ('AUTH_TOKEN_ALGORITHM', environ.get('AUTH_TOKEN_ALGORITHM', 'HS256')),
            ('AUTH_TOKEN_TIMEOUT', int(environ.get('AUTH_TOKEN_TIMEOUT', 300))),
            ('AUTH_TOKEN_SECRET', pub_key),
            ('AUTH_TOKEN_PUB_KEY', pub_key),
            ('AUTH_TOKEN_KEY_FORMAT', 'pem'),
            ('VLAB_URL', environ.get('VLAB_URL', 'https://localhost')),
          ])

Constants = namedtuple('Constants', list(DEFINED.keys()))

# The '*' expands the list, just liked passing a function *args
const = Constants(*list(DEFINED.values()))
