privacyidea-ldap-proxy
======================

`ldap-proxy` is implemented as a [twistd plugin](http://twistedmatrix.com/documents/current/core/howto/tap.html).

Installation
------------

    virtualenv2 venv
    . ./venv/bin/activate
    pip install -r requirements.txt
    pip install -e .

Configuration
-------------

`ldap-proxy` is configured via a configuration file. See `example-proxy.ini` as an example.

Running
-------

In the foreground:

    twistd -n ldap-proxy -c config.ini

