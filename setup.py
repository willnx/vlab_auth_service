#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
Auth RESTful endpoints for vLab
"""
from setuptools import setup, find_packages


setup(name="vlab-auth-service",
      author="Nicholas Willhite,",
      author_email='willnx84@gmail.com',
      version='0.0.1',
      packages=find_packages(),
      include_package_data=True,
      package_files={'vlab_auth_service' : ['app.ini']},
      description="An authentication server for vLab",
      install_requires=['flask', 'ldap3', 'pyjwt', 'uwsgi', 'vlab-api-common',
                        'ujson', 'cryptography', 'redis']
      )
