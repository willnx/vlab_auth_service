###########################
vLab Authentication Service
###########################

This service provides `JSON Web Tokens <https://jwt.io>`_ (JWT) that identifies users.
The idea is that other applications will determine authorization based on the
user's identity. By using JWT those other applications have cryptographically
secure proof that tokens have not been modified, haven't expired, and where
issued by this service alone.

************
How it works
************

It uses the LDAP protocol to lookup users in Microsoft AD, verify their credentials
and obtain group membership information. Their group memberOf information and
samAccountName is stored in the token. In production, those tokens will be
signed with an RSA private key. Other applications that consume these tokens
can verify the signature with the publicly available key.

By default, JWTs cannot be revoked; they expire after a defined period of time.
To enable users to delete tokens, and address issues with clock tampering, this
service contains a database of tokens that have not been deleted or expired.
The consuming applications can perform an HTTP GET and supply the token for resources
that require a higher level of scrutiny/control.

*********
Deploying
*********

The easiest way to run the vLab Authentication Service is with the pre-built
docker container `willnx/vlab_auth_service`

.. code-block:: shell

   $ docker run -it --rm -p 5000:5000 willnx/vlab_auth_service

If you have `docker-compose <https://docs.docker.come/composes>`_ installed, here's
an example compose file for a dev/test environment would look like:

.. code-block:: yaml

   version: '3'
   services:
     auth-api:
      sysctls:
        - net.core.somaxconn=1024
      ports:
        - "5000:5000"
      image:
        willnx/vlab-auth-service
      environment:
        - VLAB_URL=https://localhost
        - AUTH_LDAP_URL=ldaps://my.real.dc.corp
        - AUTH_BASE=my.real.dc.corp
     auth-redis:
      image:
        redis:3.2-alpine
      sysctls:
        - net.core.somaxconn=1024

In product, you need to use something like `HAProxy <http://haproxy.org>`_ or
`NGINX <https://nginx.com>`_ to perform `TLS termination <https://en.wikipedia.org/wiki/TLS_termination_proxy>`_
and (if needed) load balance between multiple instances of the `auth-api` service.

**************
Configurations
**************

The default values assume a testing environment. If you are running a Redis server
and LDAP server on the local machine, you should not need to adjust anything for
testing.

.. note::
  Make sure to increase the `somaxconn` sysctl of your Linux server to at least
  1024.

Production
==========

The RSA key pair
----------------

The public and private RSA key pairs must be localted at:
 - `/etc/vlab/auth_server/private.key`
 - `/etc/vlab/auth_server/public.key`

If you need to generate a key pair and have openssl installed, try this:

.. code-block:: shell

   $ openssl genrsa -out private.key 4096
   $ openssl rsa -in private.key -pubout > public.key


Environment variables
---------------------

The other configurations are defined by environment variables. Changing these
environment variables while the server is running **will not** modify the behavior
of the service. These variables are only ever read during application startup.

Here's a list of the environment variables to set, and what they mean:

- `AUTH_REDIS_HOSTNAME`: The FQDN or IP of the Redis server used to store the JWTs
- `AUTH_REDIS_PORT`: Only set if you *do not* use the default port for Redis
- `AUTH_LDAP_URL`: The FQDN for the domain controller(s). Prefix with `ldaps://` or `ldap://`
- `AUTH_BASE`: The Microsoft UPN suffix of the domain (i.e. the stuff after the `@`; bob@some.domain.corp)
- `AUTH_SEARCH_BASE`: The LDAP domain format (i.e. `DC=some,DC=domain,DC=corp`)
- `AUTH_TOKEN_ALGORITHM`: Should be either `RSA512` or `RSA256` in production.
- `AUTH_TOKEN_TIMEOUT`: How long, in seconds, until the token will expire.
- `VLAB_URL`: The FQDN of your instance of this service, prefixed with `https://`


************
API Examples
************

Here are some examples of interacting with the RESTful API. To make the examples
easier to read, the JWTs are shorted to `asdf.asdf.asdf`.

The Python examples use the `requests <http://docs.python-requests.org/en/master>`_ library because it's great!

Obtaining a token
=================

Python
------

.. code-block:: python

   import requests
   resp = requests.post('https://localhost:5000/api/1/auth/token', json={'username' : 'sam', 'password': 'iLoveCats'})
   token = resp.json()['token']

cURL
----

.. code-block:: shell

   $ curl --fail -X POST -H "Content-Type: application/json" -d '{"username": "sam", "password": "iLoveCats"}' https://localhost:5000/api/1/auth/token


Deleting a token
================

Python
------

.. code-block:: python

   import requests
   resp = requests.delete('https://localhost:5000/api/1/auth/token', json={'token' : 'asdf.asdf.asdf'})
   resp.status_code

cURL
----

.. code-block:: shell

   $ curl --fail -X DELETE -H "Content-Type: application/json" -d '{"token": "asdf.asdf.asdf"}' https://localhost:5000/api/1/auth/token

Verifying a token
=================

Python
------

.. code-block:: python

   import requests
   resp = requests.get('https:/localhost:5000/api/1/auth/token', params={'token' : 'asdf.asdf.asdf'})
   resp.status_code

cURL
----

.. code-block:: shell

   $ curl --fail https://localhost:5000/api/1/auth/token?token=asdf.asdf.asdf

Obtaining the public key, and checking the user's identity
==========================================================

Python
------

This example uses the `pyjwt` library for decoding the JWT.

.. code-block::

   import jwt
   import requests
   resp = requests.get('https://localhost:5000/api/1/auth/key')
   data = resp.json()
   public_key = data['key']
   algorithm = data['algorithm']
   token = 'asdf.asdf.asdf'
   user_info = jwt.decode(token, public_key, algorithm=algorithm)
