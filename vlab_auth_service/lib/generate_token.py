# -*- coding: UTF-8 -*-
"""
This module will generate an auth token use in vLab
"""
import jwt

from vlab_auth_service.lib import const


def generate_token(username, version, memberOf, issued_at_timestamp):
    """Creates the JSON Web Token

    :Returns: String

    :param username: The name of person who the token identifies
    :type username: String

    :param version: The version number for the token
    :type version: Integer/String

    :param memberOf: The LDAP attribute "memberOf" for the user
    :type memeberOf: List
    """
    claims = {'exp' : issued_at_timestamp + const.AUTH_TOKEN_TIMEOUT,
              'iat' : issued_at_timestamp,
              'iss' : const.VLAB_URL,
              'username' : username,
              'version' : version,
              'memberOf' : memberOf,
             }
    return jwt.encode(claims, const.AUTH_TOKEN_SECRET, algorithm=const.AUTH_TOKEN_ALGORITHM)


def generate_v2_token(username, version, client_ip, issued_at_timestamp, email=''):
    """Creates the JSON Web Token with a new schema

    :Returns: String

    :param username: The name of person who the token identifies
    :type username: String

    :param version: The version number for the token
    :type version: Integer/String

    :param client_ip: The IP of machine the client used to request a token.
    :type client_ip: String

    :param email: The email address associated with a user.
    :type email: String
    """
    claims = {'exp' : issued_at_timestamp + const.AUTH_TOKEN_TIMEOUT,
              'iat' : issued_at_timestamp,
              'iss' : const.VLAB_URL,
              'username' : username,
              'version' : version,
              'client_ip' : client_ip,
              'email' : email,
             }
    return jwt.encode(claims, const.AUTH_TOKEN_SECRET, algorithm=const.AUTH_TOKEN_ALGORITHM)
