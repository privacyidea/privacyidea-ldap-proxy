from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet import defer, error, reactor

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

    @defer.inlineCallbacks
    def test_health_check_closes_connection_to_backend(self):
        server, client = self.create_server_and_client()
        server.connectionLost(error.ConnectionDone)
        # Trick to ensure that the rest of the test is executed after the
        # fake connection to the backend has been established
        d = defer.Deferred()
        reactor.callLater(0, d.callback, None)
        yield d
        self.assertIsNone(server.client)
        self.assertFalse(server.clientTestDriver.connected)
        self.assertEqual(server.queuedRequests, [])

class TestProxyIgnoringReferences(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }
    additional_config = {
        'ldap-proxy': {
            'ignore-search-result-references': True,
            'allow-search': True,
        }
    }

    @defer.inlineCallbacks
    def test_ignores_search_result_reference(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client(
            [
                pureldap.LDAPBindResponse(resultCode=0)
            ],
            [
                pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
                pureldap.LDAPSearchResultReference(), # NOTE: ldaptor does not really support these
                pureldap.LDAPSearchResultReference(),
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
            ]
        )
        yield client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        entry = LDAPEntry(client, 'cn=users,dc=test,dc=local')
        r = yield entry.search('(objectClass=*)', scope=pureldap.LDAP_SCOPE_wholeSubtree)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0].dn, dn)

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

class TestProxyReuseNoServiceBind(ProxyTestCase):
    additional_config = {
        'ldap-proxy': {
            'allow-connection-reuse': True,
            'bind-service-account': False,
            'allow-search': True,
        }
    }
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    @defer.inlineCallbacks
    def test_state_reset(self):
        # Passthrough Bind, User Bind
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        search_response = pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])])
        server, client = self.create_server_and_client(
            [
                pureldap.LDAPBindResponse(resultCode=0)
            ],
            [
                 search_response,
                 pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
            ],
            [
                pureldap.LDAPBindResponse(resultCode=0)
            ]
        )
        yield client.bind('uid=passthrough,cn=users,dc=test,dc=local', 'some-secret')
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=passthrough,cn=users,dc=test,dc=local', auth='some-secret'),
        )
        # perform a search
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectcLAsS=App-markerSecret))', scope=pureldap.LDAP_SCOPE_baseObject)
        # check that the state is correct
        self.assertTrue(server.received_bind_request)
        self.assertTrue(server.forwarded_passthrough_bind)
        self.assertEqual(server.search_response_entries, 0)
        self.assertIsNone(server.last_search_response_entry)
        yield client.bind(dn, 'secret')
        self.assertEqual(len(server.client.sent), 2)
        # Check that the bind requests was sent properly
        self.assertEqual(server.client.sent[0],
                         pureldap.LDAPBindRequest(dn='uid=passthrough,cn=users,dc=test,dc=local', auth='some-secret'))
        # check that state is properly reset
        self.assertTrue(server.received_bind_request)
        self.assertFalse(server.forwarded_passthrough_bind)
        self.assertEqual(server.search_response_entries, 0)
        self.assertIsNone(server.last_search_response_entry)

class TestProxyForwardAnonymousBind(ProxyTestCase):
    additional_config = {
        'ldap-proxy': {
            'forward-anonymous-binds': True,
        }
    }

    @defer.inlineCallbacks
    def test_anonymous_bind_succeeds(self):
        server, client = self.create_server_and_client([pureldap.LDAPBindResponse(resultCode=0)])
        yield client.bind('', '')
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='', auth=''),
        )
