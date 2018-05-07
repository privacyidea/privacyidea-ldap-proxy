from ldaptor.protocols.ldap import ldaperrors
from twisted.internet import defer
from twisted.web.client import BrowserLikePolicyForHTTPS

from pi_ldapproxy.test.util import ProxyTestCase
from pi_ldapproxy.util import DisabledVerificationPolicyForHTTPS


class TestHTTPSPolicyDefault(ProxyTestCase):
    def test_browserlike(self):
        server, client = self.create_server_and_client([])
        self.assertIsInstance(server.factory.agent._endpointFactory._policyForHTTPS,
                              BrowserLikePolicyForHTTPS)


class TestHTTPSPolicyDisabled(ProxyTestCase):
    additional_config = {
        'privacyidea': {
            'verify': False,
        }
    }

    def test_disabled(self):
        server, client = self.create_server_and_client([])
        self.assertIsInstance(server.factory.agent._endpointFactory._policyForHTTPS,
                              DisabledVerificationPolicyForHTTPS)