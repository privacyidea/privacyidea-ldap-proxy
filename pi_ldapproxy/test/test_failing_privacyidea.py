from ldaptor.protocols.ldap import ldaperrors
from twisted.internet import defer

from pi_ldapproxy.test.util import ProxyTestCase


class TestFailingPrivacyIDEA(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    def test_bind_fails_internal_server_error(self):
        server, client = self.create_server_and_client([])
        self.privacyidea.response_code = 500
        d = client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    def test_bind_fails_status_false(self):
        server, client = self.create_server_and_client([])
        self.privacyidea.status = False
        d = client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)