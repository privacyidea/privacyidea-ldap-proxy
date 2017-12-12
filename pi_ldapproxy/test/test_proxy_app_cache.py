import time
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet import defer

from pi_ldapproxy.test.util import ProxyTestCase


class TestProxyUserBind(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@realmSecret': 'secret',
        'hugo@realmOfficial': 'password',
    }

    additional_config = {
        'ldap-proxy': {
            'bind-service-account': True,
            'allow-search': True,
        },
        'realm-mapping': {
            'strategy': 'app-cache',
            'mappings': {
                'markerSecret': 'realmSecret',
                'markerOfficial': 'realmOfficial',
            }
        },
        'app-cache': {
            'enabled': True,
            'timeout': 1,
        }
    }

    def test_simple_bind_fails(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client()
        d = client.bind(dn, 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    @defer.inlineCallbacks
    def _test_realm_mapping(self, marker, realm, password):
        service_dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(service_dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=service_dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectcLAsS=App-%s))' % marker, scope=pureldap.LDAP_SCOPE_baseObject)
        # sleep half a second and then try to bind as hugo
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account (successful hugo bind)
        ])
        yield client2.bind(dn, password)
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', realm, password, True)])
        time.sleep(1) # to clean the reactor

    def test_realm_mapping_succeeds1(self):
        return self._test_realm_mapping('markerSecret', 'realmSecret', 'secret')

    def test_realm_mapping_succeeds2(self):
        return self._test_realm_mapping('markerOfficial', 'realmOfficial', 'password')

    @defer.inlineCallbacks
    def test_realm_mapping_fails_wrong_password(self):
        marker = 'markerSecret'
        realm = 'realmSecret'
        password = 'password' # this is the wrong password!
        service_dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(service_dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=service_dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectclass=App-%s))' % marker, scope=pureldap.LDAP_SCOPE_baseObject)
        # sleep a second and then try to bind as hugo
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account (successful hugo bind)
        ])
        d = client2.bind(dn, password)
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', realm, password, False)])
        time.sleep(1) # to clean the reactor

    @defer.inlineCallbacks
    def test_realm_mapping_fails_wrong_marker(self):
        marker = 'markerUnknown'
        password = 'password'
        service_dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(service_dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=service_dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectclass=App-%s))' % marker, scope=pureldap.LDAP_SCOPE_baseObject)
        # sleep half a second and then try to bind as hugo
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account (successful hugo bind)
        ])
        d = client2.bind(dn, password)
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)
        self.assertEqual(self.privacyidea.authentication_requests,
                         [])
        time.sleep(1) # to clean the reactor

    @defer.inlineCallbacks
    def test_realm_mapping_fails_case_sensitive(self):
        marker = 'markerSecret'
        password = 'secret'
        service_dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        dn = 'uid=Hugo,cn=users,dc=test,DC=LOCAL'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(service_dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=service_dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectclass=App-%s))' % marker, scope=pureldap.LDAP_SCOPE_baseObject)
        # sleep half a second and then try to bind as hugo
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account (successful hugo bind)
        ])
        d = client2.bind(dn.lower(), password) # this will fail because the DN has differing case
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)
        self.assertEqual(self.privacyidea.authentication_requests,
                         [])
        time.sleep(1) # to clean the reactor

    @defer.inlineCallbacks
    def test_realm_mapping_fails_waiting_too_long(self):
        service_dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        marker = 'markerSecret'
        password = 'secret'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(service_dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=service_dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectclass=App-%s))' % marker, scope=pureldap.LDAP_SCOPE_baseObject)
        # sleep very long and then try to bind as hugo
        time.sleep(2)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account (successful hugo bind)
        ])
        d = client2.bind(dn, password)
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)
        self.assertEqual(self.privacyidea.authentication_requests,
                         [])
        time.sleep(1) # to clean the reactor

    @defer.inlineCallbacks
    def test_realm_mapping_fails_fake_search_by_user(self):
        service_dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(service_dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=service_dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectcLAsS=App-markerSecret))', scope=pureldap.LDAP_SCOPE_baseObject)
        # sleep half a second and then try to bind as hugo
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account (successful hugo bind)
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]), # hugo's search
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client2.bind(dn, 'secret')
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'realmSecret', 'secret', True)])
        # Perform another search in hugo's context
        entry2 = LDAPEntry(client2, dn)
        r = yield entry2.search('(|(objectClass=*)(objectcLAsS=App-markerOfficial))', scope=pureldap.LDAP_SCOPE_baseObject)
        self.assertTrue(server.factory.app_cache.get_cached_marker(dn) in ('markerSecret', None))
        time.sleep(1) # to clean the reactor

class TestProxyUserBindCaseInsensitive(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@realmSecret': 'secret',
        'hugo@realmOfficial': 'password',
    }

    additional_config = {
        'ldap-proxy': {
            'bind-service-account': True,
            'allow-search': True,
        },
        'realm-mapping': {
            'strategy': 'app-cache',
            'mappings': {
                'markerSecret': 'realmSecret',
                'markerOfficial': 'realmOfficial',
            },
        },
        'app-cache': {
            'enabled': True,
            'timeout': 1,
            'case-insensitive': True,
        }
    }

    @defer.inlineCallbacks
    def test_realm_mapping_succeeds_case_sensitive(self):
        marker = 'markerSecret'
        password = 'secret'
        service_dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        dn = 'uid=Hugo,cn=users,dc=test,DC=LOCAL'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(service_dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=service_dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        r = yield entry.search('(|(objectClass=*)(objectclass=App-%s))' % marker, scope=pureldap.LDAP_SCOPE_baseObject)
        # sleep half a second and then try to bind as hugo
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account (successful hugo bind)
        ])
        yield client2.bind(dn.lower(), password) # this will work even though the DN has differing case
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'realmSecret', password, True)])
        time.sleep(1) # to clean the reactor