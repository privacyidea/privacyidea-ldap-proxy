import twisted
from ldaptor.ldapfilter import parseFilter
from ldaptor.protocols import pureldap

from pi_ldapproxy.realmmapping import find_app_marker, detect_login_preamble


class TestRealmMapping(twisted.trial.unittest.TestCase):
    def test_find_app_marker(self):
        filter = parseFilter('(&(|(objectclass=person)(objectclass=App-someApp))(cn=user123))')
        self.assertEqual(find_app_marker(filter), 'someApp')

        filter = parseFilter('(&(|(objectclass=person)(someOtherAttribute=App-someApp))(cn=user123))')
        self.assertIsNone(find_app_marker(filter))
        self.assertEqual(find_app_marker(filter, attribute='someOtherAttribute'), 'someApp')

        filter = parseFilter('(&(|(objectclass=person)(someOtherAttribute=Prefix-someApp))(cn=user123))')
        self.assertEqual(find_app_marker(filter, attribute='someOtherAttribute', value_prefix='Prefix-'), 'someApp')

        filter = parseFilter('(&(|(objectclass=person))(cn=user123))')
        self.assertIsNone(find_app_marker(filter))

    def test_detect_login_preamble(self):
        filter = parseFilter('(&(|(objectclass=person)(objectclass=App-someApp))(cn=user123))')
        request = pureldap.LDAPSearchRequest(baseObject='cn=users,dc=test,dc=local',
                                  scope=pureldap.LDAP_SCOPE_wholeSubtree, derefAliases=0,
                                  sizeLimit=0, timeLimit=0, typesOnly=0,
                                  filter=filter,
                                  attributes=())
        dn = 'cn=user123,cn=users,dc=test,dc=local'
        response = pureldap.LDAPSearchResultEntry(dn, [('cn', ['user123'])])
        self.assertEqual(detect_login_preamble(request, response), (dn, 'someApp'))

        self.assertIsNone(detect_login_preamble(request, pureldap.LDAPSearchResultDone(0)))

        filter = parseFilter('(&(|(objectclass=person)(someATTRIBuTE=Foo-someApp))(cn=user123))')
        request = pureldap.LDAPSearchRequest(baseObject='cn=users,dc=test,dc=local',
                                             scope=pureldap.LDAP_SCOPE_wholeSubtree, derefAliases=0,
                                             sizeLimit=0, timeLimit=0, typesOnly=0,
                                             filter=filter,
                                             attributes=())
        dn = 'cn=user123,cn=users,dc=test,dc=local'
        response = pureldap.LDAPSearchResultEntry(dn, [('cn', ['user123'])])
        self.assertEqual(detect_login_preamble(request, response, 'someAttribute', 'Foo-'), (dn, 'someApp'))
