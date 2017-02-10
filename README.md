privacyidea-ldap-proxy
======================

`ldap-proxy` is implemented as a [twistd plugin](http://twistedmatrix.com/documents/current/core/howto/tap.html).

Installation
------------

It is recommended to install ldap-proxy inside a virtualenv.

    virtualenv2 venv
    . ./venv/bin/activate
    pip install -r requirements.txt
    pip install .

If you wish to develop ldap-proxy, you could instead install it in "editable mode" using

    pip install -e .

Configuration
-------------

`ldap-proxy` is configured via a configuration file. See `example-proxy.ini` as an example.

Running
-------

ldap-proxy can be run in the foreground as follows:

    twistd -n ldap-proxy -c config.ini

twistd can be used to configure, e.g., logging and daemonizing. Refer to its
[documentation](https://twistedmatrix.com/documents/current/core/howto/basics.html) for more information.

`deploy` contains an exemplary systemd service file.

Testing
-------

Unit tests are implemented using [Trial](http://twistedmatrix.com/documents/current/core/howto/trial.html), which
is part of Twisted. They can be run using:

    trial tests/

There are also a number of client-side scenarios implemented in the `scenarios/` directory.