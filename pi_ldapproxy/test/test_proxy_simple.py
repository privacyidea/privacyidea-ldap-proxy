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

    @defer.inlineCallbacks
    def test_reusing_connection_fails1(self):
        # Scenario 1: Passthrough Bind, User Bind
        server, client = self.create_server_and_client([pureldap.LDAPBindResponse(resultCode=0)])
        yield client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=passthrough,cn=users,dc=test,dc=local', auth='some-secret'),
        )
        d = client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    @defer.inlineCallbacks
    def test_reusing_connection_fails2(self):
        # Scenario 2: User Bind, Passthrough Bind
        server, client = self.create_server_and_client([pureldap.LDAPBindResponse(resultCode=0)])
        yield client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        d = client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    @defer.inlineCallbacks
    def test_reusing_connection_fails3(self):
        # Scenario 3: Passthrough Bind, Passthrough Bind
        server, client = self.create_server_and_client([pureldap.LDAPBindResponse(resultCode=0)])
        yield client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        d = client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=passthrough,cn=users,dc=test,dc=local', auth='some-secret'),
        )

    @defer.inlineCallbacks
    def test_reusing_connection_fails4(self):
        # Scenario 4: User Bind, User Bind
        server, client = self.create_server_and_client([])
        yield client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        d = client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

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

class TestProxyReuse(ProxyTestCase):
    additional_config = {
        'ldap-proxy': {
            'allow-connection-reuse': True,
            'bind-service-account': True,
        }
    }
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    @defer.inlineCallbacks
    def test_reusing_connection_succeeds1(self):
        # Passthrough Bind, User Bind
        server, client = self.create_server_and_client(
            [
                pureldap.LDAPBindResponse(resultCode=0)
            ],
            [
                pureldap.LDAPBindResponse(resultCode=0)
            ])
        yield client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        yield client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=passthrough,cn=users,dc=test,dc=local', auth='some-secret'),
            pureldap.LDAPBindRequest(dn='uid=service,cn=users,dc=test,dc=local', auth='service-secret'),
        )

    @defer.inlineCallbacks
    def test_reusing_connection_succeeds2(self):
        # User Bind, User Bind
        server, client = self.create_server_and_client(
            [
                pureldap.LDAPBindResponse(resultCode=0)
            ],
            [
                pureldap.LDAPBindResponse(resultCode=0)
            ])
        yield client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        yield client.bind('uid=hugo,cn=users,dc=test,dc=local', 'secret')
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=service,cn=users,dc=test,dc=local', auth='service-secret'),
            pureldap.LDAPBindRequest(dn='uid=service,cn=users,dc=test,dc=local', auth='service-secret'),
        )