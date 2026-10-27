from twisted.trial.unittest import TestCase

from pi_ldapproxy.config import load_config
from pi_ldapproxy.realmmapping import RegexMappingStrategy
from pi_ldapproxy.test.util import BASE_CONFIG


class TestRegexConfig(TestCase):
    def load_realm_config(self, options=''):
        content = BASE_CONFIG.replace(
            '[realm-mapping]\nstrategy = static\nrealm = default',
            '[realm-mapping]\nstrategy = regex\n' + options)
        filename = self.mktemp()
        with open(filename, 'w') as config_file:
            config_file.write(content)
        return load_config(filename)['realm-mapping']

    def test_defaults(self):
        config = self.load_realm_config()
        self.assertEqual(config['realm'], '')
        self.assertIs(config['case-insensitive'], False)

    def test_false_is_parsed_as_boolean(self):
        config = self.load_realm_config('case-insensitive = false')
        self.assertIs(config['case-insensitive'], False)

    def test_invalid_boolean_is_rejected(self):
        self.assertRaises(SystemExit, self.load_realm_config, 'case-insensitive = invalid')

    def test_quoted_dn_pattern_and_boolean_reach_mapper(self):
        config = self.load_realm_config('''realm = fallback
case-insensitive = true
[[mappings]]
users = "^cn=[^,]+,ou=users,dc=example,dc=com$"
''')
        self.assertIs(config['case-insensitive'], True)
        self.assertEqual(config['mappings']['users'],
                         '^cn=[^,]+,ou=users,dc=example,dc=com$')
        mapper = RegexMappingStrategy(None, config)
        self.assertEqual(self.successResultOf(mapper.resolve(
            'CN=alice,OU=users,DC=example,DC=com')), ('users', 'users'))
        self.assertEqual(self.successResultOf(mapper.resolve(
            'cn=bob,ou=other,dc=example,dc=com')), ('fallback', 'fallback'))
