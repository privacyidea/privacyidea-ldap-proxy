LDAP Proxy Scenarios
====================

The scripts in this directory implement the client side of some exemplary scenarios involving the LDAP server.
They could, for example, be used to test the LDAP proxy.

The scripts are best run in a virtualenv:

    virtualenv2 venv
    . ./venv/bin/activate
    pip install -r requirements.txt

They are configured in a file `config.ini`. `example-config.ini` provides an exemplary configuration.

Each script's header contains a docstring explaining the respective scenario.