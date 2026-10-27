from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from twisted.internet import defer

from pi_ldapproxy.test.util import ProxyTestCase


class TestProxyRegexRealmMapping(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@users': 'secret',
        'hugo@admins': 'admin-secret',
        'hugo@fallback': 'fallback-secret',
        'hugo@': 'default-secret',
    }

    additional_config = {
        'user-mapping': {
            'pattern': r'^uid=([^,]+),cn=[^,]+,dc=test,dc=local$',
        },
        'realm-mapping': {
            'strategy': 'regex',
            'realm': 'fallback',
            'case-insensitive': True,
            'mappings': {
                'users': r'^uid=[^,]+,cn=users,dc=test,dc=local$',
                'admins': r'^uid=[^,]+,cn=admins,dc=test,dc=local$',
            },
        },
    }

    @defer.inlineCallbacks
    def check_bind(self, dn, realm, password):
        server, client = self.create_server_and_client()
        yield client.bind(dn, password)
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', realm, password, True)])
        server.client.assertNothingSent()

    def test_user_realm(self):
        return self.check_bind('uid=hugo,cn=users,dc=test,dc=local', 'users', 'secret')

    def test_admin_realm(self):
        return self.check_bind('uid=hugo,cn=admins,dc=test,dc=local', 'admins', 'admin-secret')

    def test_case_insensitive_dn(self):
        return self.check_bind('UID=hugo,CN=USERS,DC=TEST,DC=LOCAL', 'users', 'secret')

    def test_fallback_realm(self):
        return self.check_bind('uid=hugo,cn=other,dc=test,dc=local', 'fallback', 'fallback-secret')

    def test_empty_realm(self):
        self.factory.realm_mapper.realm = ''
        return self.check_bind('uid=hugo,cn=other,dc=test,dc=local', '', 'default-secret')

    @defer.inlineCallbacks
    def test_wrong_password_is_rejected(self):
        server, client = self.create_server_and_client()
        yield self.assertFailure(client.bind('uid=hugo,cn=users,dc=test,dc=local', 'wrong'),
                                 ldaperrors.LDAPInvalidCredentials)
        self.assertEqual(self.privacyidea.authentication_requests,
                         [('hugo', 'users', 'wrong', False)])
        server.client.assertNothingSent()

    @defer.inlineCallbacks
    def test_passthrough_bypasses_realm_mapping(self):
        def unexpected_resolution(dn):
            self.fail('Passthrough bind must not resolve a realm')

        self.patch(self.factory.realm_mapper, 'resolve', unexpected_resolution)
        dn = 'uid=passthrough,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client([
            pureldap.LDAPBindResponse(resultCode=0),
        ])
        yield client.bind(dn, 'service-secret')
        server.client.assertSent(pureldap.LDAPBindRequest(dn=dn, auth='service-secret'))
        self.assertEqual(self.privacyidea.authentication_requests, [])
