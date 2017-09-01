import time
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet import defer

from pi_ldapproxy.test.util import ProxyTestCase


class TestProxyUserBind(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret',
    }

    additional_config = {
        'bind-cache': {
            'enabled': True,
            'timeout': 2,
        }
    }

    @defer.inlineCallbacks
    def test_simple_bind_succeeds(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client()
        yield client.bind(dn, 'secret')
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'default', 'secret', True)])
        time.sleep(3) # clean bind cache

    @defer.inlineCallbacks
    def test_subsequent_binds_succeed(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ])
        yield client.bind(dn, 'secret')
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account
        ])
        yield client2.bind(dn, 'secret')
        # but only one authentication request to privacyIDEA!
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'default', 'secret', True)])
        time.sleep(2) # to clean the reactor

    @defer.inlineCallbacks
    def test_bind_cache_cleared(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ])
        yield client.bind(dn, 'secret')
        time.sleep(3) # which cleans the bind cache
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account
        ])
        yield client2.bind(dn, 'secret')
        # two authentication requests to privacyIDEA!
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'default', 'secret', True),
                          ('hugo', 'default', 'secret', True)])
        time.sleep(2) # to clean the reactor

    @defer.inlineCallbacks
    def test_bind_cache_different_password(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ])
        yield client.bind(dn, 'secret')
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ])
        d = client2.bind(dn, 'something-else')
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)
        # two authentication requests to privacyIDEA!
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'default', 'secret', True),
                          ('hugo', 'default', 'something-else', False)])
        time.sleep(2) # to clean the reactor

    @defer.inlineCallbacks
    def test_bind_cache_different_password(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ])
        yield client.bind(dn, 'secret')
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ])
        d = client2.bind(dn, 'something-else')
        yield self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)
        # two authentication requests to privacyIDEA!
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'default', 'secret', True),
                          ('hugo', 'default', 'something-else', False)])
        time.sleep(2) # to clean the reactor

    @defer.inlineCallbacks
    def test_bind_cache_different_app(self):
        dn = 'uid=hugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ])
        yield client.bind(dn, 'secret')
        time.sleep(0.5)
        server2, client2 = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),  # for service account
        ])
        # Monkey-patch the realm mapper (this is suboptimal)
        _old_resolve = self.factory.realm_mapper.resolve
        # Model a second app which maps to the same realm
        self.factory.realm_mapper.resolve = lambda dn: defer.succeed(('other-app', 'default'))
        yield client2.bind(dn, 'secret')
        # two authentication requests to privacyIDEA!
        # this means that the second request was not taken from the bind cache
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'default', 'secret', True),
                          ('hugo', 'default', 'secret', True)])
        time.sleep(2) # to clean the reactor
        self.factory.realm_mapper.resolve = _old_resolve