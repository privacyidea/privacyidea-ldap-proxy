from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet import defer

from pi_ldapproxy.test.util import ProxyTestCase


class TestProxySimple(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    def test_anonymous_bind_fails(self):
        server, client = self.create_server_and_client([])
        d = client.bind('', '')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    @defer.inlineCallbacks
    def test_bind_succeeds(self):
        server, client = self.create_server_and_client([])
        yield client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')

    def test_bind_fails_wrong_password(self):
        server, client = self.create_server_and_client([])
        d = client.bind('uid=hugo,cn=users,dc=test,dc=local', 'wrong')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    def test_bind_fails_unknown_user(self):
        server, client = self.create_server_and_client([])
        d = client.bind('uid=unknown,cn=users,dc=test,dc=local', 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    def test_bind_fails_no_matching_dn(self):
        server, client = self.create_server_and_client([])
        d = client.bind('uid=hugo,cn=users,dc=somewhere-else,dc=local', 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    def test_bind_fails_invalid_dn(self):
        server, client = self.create_server_and_client([])
        d = client.bind('dn=uid=hugo,cn=users,dc=test,dc=local', 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    @defer.inlineCallbacks
    def test_passthrough_bind_succeeds(self):
        server, client = self.create_server_and_client([pureldap.LDAPBindResponse(resultCode=0)])
        yield client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=passthrough,cn=users,dc=test,dc=local', auth='some-secret'),
        )

    def test_passthrough_bind_fails(self):
        server, client = self.create_server_and_client([pureldap.LDAPBindResponse(resultCode=49)])
        d = client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    @defer.inlineCallbacks
    def test_passthrough_account_search_fails(self):
        server, client = self.create_server_and_client([pureldap.LDAPBindResponse(resultCode=0)])
        yield client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        entry = LDAPEntry(client, 'cn=users,dc=test,dc=local')
        d = entry.search('(objectClass=*)', scope=pureldap.LDAP_SCOPE_wholeSubtree)
        yield self.assertFailure(d, ldaperrors.LDAPInsufficientAccessRights)
