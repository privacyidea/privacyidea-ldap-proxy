from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from twisted.internet import defer

from pi_ldapproxy.test.util import ProxyTestCase


class TestProxyUserLookup(ProxyTestCase):
    privacyidea_credentials = {
        'hugo@default': 'secret'
    }

    additional_config = {
        'user-mapping': {
            'strategy': 'lookup',
            'attribute': 'sAMAccountName'
        }
    }

    @defer.inlineCallbacks
    def test_simple_bind(self):
        dn = 'uid=thegreathugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client()
        service_account_client = self.inject_service_account_server([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('sAMAccountName', ['hugo'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        yield client.bind(dn, 'secret')
        # Assert that Proxy<->Backend (the actual connection) did not send anything
        server.client.assertNothingSent()
        # Assert that Proxy<->Backend (the lookup connection) did send something
        service_account_client.assertSent(
            pureldap.LDAPBindRequest(dn='uid=service,cn=users,dc=test,dc=local', auth='service-secret'),
            pureldap.LDAPSearchRequest(baseObject='uid=thegreathugo,cn=users,dc=test,dc=local', scope=0, derefAliases=0,
                              sizeLimit=0, timeLimit=0, typesOnly=0,
                              filter=pureldap.LDAPFilter_present(value='objectClass'),
                              attributes=()),
            'fake-unbind-by-LDAPClientTestDriver'
        )

    def test_missing_attribute(self):
        dn = 'uid=thegreathugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client()
        service_account_client = self.inject_service_account_server([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultEntry(dn, [('someOtherAttribute', ['hugo'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ])
        d = client.bind(dn, 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)

    def test_unknown_user(self):
        dn = 'uid=thegreathugo,cn=users,dc=test,dc=local'
        server, client = self.create_server_and_client()
        service_account_client = self.inject_service_account_server([
            pureldap.LDAPBindResponse(resultCode=0), # for service account
        ], [
            pureldap.LDAPSearchResultDone(ldaperrors.LDAPNoSuchObject.resultCode),
        ])
        d = client.bind(dn, 'secret')
        return self.assertFailure(d, ldaperrors.LDAPInvalidCredentials)