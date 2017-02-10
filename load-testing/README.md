privacyIDEA LDAP Proxy Load Testing
===================================

Proof-of-concept of LDAP load testing using [locust](http://locust.io)

How to run:

    virtualenv2 venv
    . ./venv/bin/activate
    pip install -r requirements.txt

Then, edit the USER_DN and USER_PASSWORD constants in `locustfile.py` and run

    locust -H 10.1.2.3

with `10.1.2.3` being the LDAP server IP and visit `127.0.0.1:8089` in your web browser.