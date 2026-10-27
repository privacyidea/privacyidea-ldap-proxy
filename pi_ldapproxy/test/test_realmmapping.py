from collections import OrderedDict

from ldaptor.ldapfilter import parseFilter
from ldaptor.protocols import pureldap
from twisted.trial.unittest import TestCase

from pi_ldapproxy.realmmapping import (
    find_app_marker, detect_login_preamble, RegexMappingStrategy, RealmMappingError,
)


class TestRealmMapping(TestCase):
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


class TestRegexMappingStrategy(TestCase):
    dn = 'cn=alice,ou=users,dc=example,dc=com'
    pattern = r'^cn=[^,]+,ou=users,dc=example,dc=com$'

    def make_mapper(self, mappings=None, **options):
        config = {'mappings': {'users': self.pattern} if mappings is None else mappings}
        config.update(options)
        return RegexMappingStrategy(None, config)

    def assert_realm(self, mapper, dn, realm):
        self.assertEqual(self.successResultOf(mapper.resolve(dn)), (realm, realm))

    def test_selects_realm_by_dn(self):
        mapper = self.make_mapper({
            'users': self.pattern,
            'admins': r'^cn=[^,]+,ou=admins,dc=example,dc=com$',
        })
        self.assert_realm(mapper, self.dn, 'users')
        self.assert_realm(mapper, 'cn=bob,ou=admins,dc=example,dc=com', 'admins')

    def test_first_match_uses_alphabetical_realm_order(self):
        mapper = self.make_mapper(OrderedDict([
            ('z-users', self.pattern), ('a-users', self.pattern),
        ]))
        self.assert_realm(mapper, self.dn, 'a-users')

    def test_matches_at_start_of_dn(self):
        mapper = self.make_mapper({'users': r'ou=users'}, realm='fallback')
        self.assert_realm(mapper, self.dn, 'fallback')

    def test_pattern_need_not_match_entire_dn(self):
        mapper = self.make_mapper({'users': r'cn=alice'})
        self.assert_realm(mapper, self.dn, 'users')

    def test_unmatched_dn_uses_configured_fallback(self):
        mapper = self.make_mapper(realm='fallback')
        self.assert_realm(mapper, 'cn=carol,ou=other,dc=example,dc=com', 'fallback')

    def test_unmatched_dn_defaults_to_empty_realm(self):
        self.assert_realm(self.make_mapper(), 'cn=carol,ou=other', '')

    def test_explicit_empty_fallback(self):
        self.assert_realm(self.make_mapper(realm=''), 'cn=carol,ou=other', '')

    def test_empty_mappings_use_fallback(self):
        self.assert_realm(self.make_mapper({}, realm='fallback'), self.dn, 'fallback')

    def test_matching_is_case_sensitive_by_default(self):
        self.assert_realm(self.make_mapper(realm='fallback'), self.dn.upper(), 'fallback')

    def test_matching_can_ignore_case(self):
        mapper = self.make_mapper(**{'case-insensitive': True})
        self.assert_realm(mapper, self.dn.upper(), 'users')

    def test_positional_capture_in_realm(self):
        mapper = self.make_mapper({'realm-{0}': r'^cn=[^,]+,ou=([^,]+),'})
        self.assert_realm(mapper, self.dn, 'realm-users')

    def test_named_capture_in_realm(self):
        mapper = self.make_mapper({'realm-{unit}': r'^cn=[^,]+,ou=(?P<unit>[^,]+),'})
        self.assert_realm(mapper, self.dn, 'realm-users')

    def test_missing_positional_capture_keeps_literal_realm(self):
        mapper = self.make_mapper({'realm-{1}': r'^cn=([^,]+),'})
        self.assert_realm(mapper, self.dn, 'realm-{1}')

    def test_missing_named_capture_keeps_literal_realm(self):
        mapper = self.make_mapper({'realm-{missing}': self.pattern})
        self.assert_realm(mapper, self.dn, 'realm-{missing}')

    def test_invalid_regex_fails_at_initialization(self):
        error = self.assertRaises(RealmMappingError, self.make_mapper, {'users': '['})
        self.assertIn('Invalid regex pattern', str(error))

    def test_list_pattern_uses_first_element(self):
        mapper = self.make_mapper({'users': [self.pattern, '[']})
        self.assert_realm(mapper, self.dn, 'users')

    def test_empty_pattern_list_is_rejected(self):
        error = self.assertRaises(RealmMappingError, self.make_mapper, {'users': []})
        self.assertIn('Empty pattern list', str(error))
