# Contains code from ldaptor (createServer from ldaptor/testutil.py),
# which is licensed under the MIT license as follows.
# Copyright (c) 2002-2014, Ldaptor Contributors (see AUTHORS)
#
# Ldaptor is licensed under the MIT license for the majority of the
# files, with exceptions listed below.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import configobj
import twisted
import validate
from ldaptor import testutil
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.test.util import returnConnected, IOPump
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.task import LoopingCall

from pi_ldapproxy.config import CONFIG_SPEC
from pi_ldapproxy.proxy import TwoFactorAuthenticationProxy, ProxyServerFactory
from pi_ldapproxy.test.mock import MockPrivacyIDEA, MockLDAPClient

BASE_CONFIG = """
[privacyidea]
instance = http://example.com

[ldap-backend]
endpoint = tcp:host=example.com:port=1337:timeout=1
use-tls = false
test-connection = false

[service-account]
dn = "uid=service,cn=users,dc=test,dc=local"
password = service-secret

[ldap-proxy]
endpoint = tcp:1389
passthrough-binds = "uid=passthrough,cn=users,dc=test,dc=local"
bind-service-account = false
allow-search = false

[user-mapping]
#strategy = lookup
#attribute = uid
strategy = match
pattern = "uid=([^,]+),cn=users,dc=test,dc=local"

[realm-mapping]
strategy = static
realm = default

[app-cache]
enabled = false

[bind-cache]
enabled = false
"""

def load_test_config():
    config = configobj.ConfigObj(BASE_CONFIG.splitlines(), configspec=CONFIG_SPEC.splitlines())
    validator = validate.Validator()
    result = config.validate(validator, preserve_errors=True)
    assert result == True, "Invalid test config"
    return config

class ProxyTestCase(twisted.trial.unittest.TestCase):
    additional_config = {}
    privacyidea_credentials = {}

    def get_config(self):
        config = load_test_config()
        for section, contents in self.additional_config.iteritems():
            for key, value in contents.iteritems():
                config[section][key] = value
        return config

    def inject_service_account_server(self, *responses):
        client = MockLDAPClient(*responses)

        @defer.inlineCallbacks
        def _factory_connect_service_account():
            client.connectionMade() # TODO: Necessary here?
            yield client.bind(self.factory.service_account_dn, self.factory.service_account_password)
            defer.returnValue(client)

        self.factory.connect_service_account = _factory_connect_service_account
        return client

    def setUp(self):
        self.factory = ProxyServerFactory(self.get_config())
        self.pump_call = LoopingCall(self.pump_all)
        self.pump_call.start(0.1)

        self.privacyidea = MockPrivacyIDEA(self.privacyidea_credentials)
        self.pumps = set()

    def tearDown(self):
        self.pump_call.stop()
        # remove all pumps that have been created
        for pump in self.pumps:
            IOPump.active.remove(pump)
        self.pumps = set()

    def pump_all(self):
        for pump in IOPump.active:
            pump.pump()

    def create_server(self, *responses, **kwds):
        """
        Create a server for each test.
        """
        protocol = kwds.get("protocol", TwoFactorAuthenticationProxy)
        server = protocol()
        clientTestDriver = MockLDAPClient(*responses)

        def simulateConnectToServer():
            d = defer.Deferred()

            def onConnect():
                clientTestDriver.connectionMade()
                d.callback(clientTestDriver)

            reactor.callLater(0, onConnect)
            return d

        clientConnector = kwds.get('clientConnector', simulateConnectToServer)
        server.clientConnector = clientConnector
        server.factory = self.factory
        server.clientTestDriver = clientTestDriver
        self.privacyidea.inject(server)
        return server

    def create_server_and_client(self, *responses, **kwds):
        client = LDAPClient()
        server = self.create_server(*responses, **kwds)
        self.pumps.add(returnConnected(server, client))
        return server, client