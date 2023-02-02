=============
Resuelve auth
=============

A python implementation of ``resuelve-auth``

Install
-------

Using ``pip``:

.. code-block:: shell

    pip install git+https://github.com/resuelve/resuelve-auth-python.git

Using ``poetry``

.. code-block:: shell

    poetry add git+https://github.com/resuelve/resuelve-auth-python.git


Usage
-----

Validate a existing token.

``ttl`` can be used to define the quantity of seconds that token will be valid.

.. code-block:: python

    from resuelve_auth import auth
    from resuelve_auth.exceptions import ResuelveAuthError

    SECRET = "some secret key"
    try:
        metadata = auth.validate_token(SECRET, "a token", ttl=10)
    except ResuelveAuthError as ex:
        # TODO: handle error here

Build a new token with some data inside of it

.. code-block:: python

    from resuelve_auth import auth

    SECRET = "some secret key"
    meta = {"some": "data"}
    token = auth.build_token(SECRET, meta)

Enjoy 🎉
