from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet import defer

from pi_ldapproxy.test.util import ProxyTestCase


class TestProxyUserBind(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    additional_config = {
        'ldap-proxy': {
            'bind-service-account': True,
            'allow-search': True,
        }
    }

    @defer.inlineCallbacks
    def test_simple_search(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(dn, 'secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=service,cn=users,dc=test,dc=local', auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        results = yield entry.search('(objectClass=*)', scope=pureldap.LDAP_SCOPE_baseObject)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0]['someattr']), 1)
        (value,) = results[0]['someattr']
        self.assertEqual(value, 'somevalue')

    def test_wrong_credentials(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        d = client.bind(dn, 'wrong')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

class TestProxyUserBindNoSearch(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    additional_config = {
        'ldap-proxy': {
            'bind-service-account': True,
            'allow-search': False,
        }
    }

    @defer.inlineCallbacks
    def test_user_search_fails(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(dn, 'secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=service,cn=users,dc=test,dc=local', auth='service-secret'),
        )
        # Try to perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        d = entry.search('(objectClass=*)', scope=pureldap.LDAP_SCOPE_baseObject)
        yield self.assertFailure(d, ldaperrors.LDAPInsufficientAccessRights)

class TestProxyPassthroughSearch(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    additional_config = {
        'ldap-proxy': {
            'bind-service-account': False,
            'allow-search': True,
        }
    }

    @defer.inlineCallbacks
    def test_user_search_fails(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            # TODO: Would the backend actually answer like that?
            pureldap.LDAPSearchResultDone(ldaperrors.LDAPInsufficientAccessRights.resultCode),
        ])
        yield client.bind(dn, 'secret')
        # Assert that there was no traffic between Proxy<->Backend
        server.client.assertNothingSent()
        # Try to perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        d = entry.search('(objectClass=*)', scope=pureldap.LDAP_SCOPE_baseObject)
        yield self.assertFailure(d, ldaperrors.LDAPInsufficientAccessRights)

    @defer.inlineCallbacks
    def test_passthrough_account_search_succeeds(self):
        dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someattr', ['somevalue'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(dn, 'service-secret')
        # Assert that Proxy<->Backend uses the correct credentials
        server.client.assertSent(
            pureldap.LDAPBindRequest(dn=dn, auth='service-secret'),
        )
        # Perform a simple search in the context of the service account
        entry = LDAPEntry(client, dn)
        results = yield entry.search('(objectClass=*)', scope=pureldap.LDAP_SCOPE_baseObject)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0]['someattr']), 1)
        (value,) = results[0]['someattr']
        self.assertEqual(value, 'somevalue')
