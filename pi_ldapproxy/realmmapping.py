from ldaptor.protocols.pureldap import LDAPFilter_and, LDAPFilter_or, LDAPFilter_equalityMatch, LDAPSearchRequest, \
    LDAPSearchResultEntry
from twisted.internet import defer
from twisted.logger import Logger
from six import ensure_str
import re

log = Logger()


def find_app_marker(filter, attribute='objectclass', value_prefix='App-'):
    """
    Given an ldaptor filter, try to extract an app marker, i.e. find
    a marker such that the filter contains an expression (<attribute>=<value_prefix><marker>),
    e.g. (objectclass=App-ownCloud).
    It may be nested in &() and |() expressions.
    :param filter: ldaptor filter
    :param attribute: attribute name whose value contains the app marker (matched case-insensitively)
    :param value_prefix: prefix of the app marker (matched case-sensitively)
    :return: None or an app marker (a string)
    """
    if isinstance(filter, LDAPFilter_and) or isinstance(filter, LDAPFilter_or):
        # recursively search and/or expressions
        for subfilter in filter:
            app_marker = find_app_marker(subfilter, attribute, value_prefix)
            if app_marker:
                return app_marker
    elif isinstance(filter, LDAPFilter_equalityMatch):
        # check attribute name and value prefix
        if ensure_str(filter.attributeDesc.value).lower() == attribute.lower():
            value = ensure_str(filter.assertionValue.value)
            if value.startswith(value_prefix):
                return value[len(value_prefix):]
    return None


def detect_login_preamble(request, response, attribute='objectclass', value_prefix='App-'):
    """
    Determine whether the request/response pair constitutes a login preamble.
    If it does, return the login DN and the app marker.
    :param request: LDAP request
    :param response: LDAP response
    :param attribute: see ``find_app_marker``
    :param value_prefix: see ``find_app_marker``
    :return: A tuple ``(DN, app marker)`` or None
    """
    if isinstance(request, LDAPSearchRequest) and request.filter:
        # TODO: Check base dn?
        marker = find_app_marker(request.filter, attribute, value_prefix)
        # i.e. we do not notice if the response has >1 entries
        if marker is not None and isinstance(response, LDAPSearchResultEntry):
            return (response.objectName, marker)
    return None


class RealmMappingError(Exception):
    pass


class RealmMappingStrategy(object):
    """
    Base class for realm mappers, which are used to determine the user's privacyIDEA realm
    from an incoming LDAP Bind Request's distinguished name.
    """
    def __init__(self, factory, config):
        """
        :param factory: `ProxyServerFactory` instance
        :param config: `[realm-mapping]` section of the config file, as a dictionary
        """
        self.factory = factory
        self.config = config

    def resolve(self, dn):
        """
        Given the distinguished name, determine the realm name or raise RealmMappingError.
        :param dn: DN as string
        :return: A Deferred which fires (app marker, realm name) (as strings)
        """
        raise NotImplementedError()


class StaticMappingStrategy(RealmMappingStrategy):
    """
    `static` mapping strategy: Simply assign the same static realm to all authentication request.

    Configuration:
        `realm` contains the realm name (can also be empty)

    """
    def __init__(self, factory, config):
        RealmMappingStrategy.__init__(self, factory, config)
        self.realm = config['realm']

    def resolve(self, dn):
        return defer.succeed((self.realm, self.realm))

class RegexMappingStrategy(RealmMappingStrategy):
    """
    `regex` mapping strategy: Use regular expressions to map DNs to realms.
    The first matching regex determines the realm. If no regex matches, 
    uses the configured realm parameter (like static strategy).

    Configuration:
        `mappings` is a subsection which maps regex patterns to realm names.
        Patterns are checked in alphabetical order of their keys, so you should
        prefix them with numbers if you want a specific order.
        
        `realm` (optional) is the realm name to use when no regex matches.
        If not specified, behaves like static strategy (empty realm).
        
        `case-insensitive` (optional) if set to true, DN matching will be 
        case-insensitive. Default is false (case-sensitive).

        e.g.:

            [realm-mapping]
            strategy = regex
            realm = default
            case-insensitive = true

            [[mappings]]
            01_ou_users = ^cn=.*,ou=users,dc=example,dc=com$
            02_ou_admins = ^cn=.*,ou=admins,dc=example,dc=com$
    """
    def __init__(self, factory, config):
        RealmMappingStrategy.__init__(self, factory, config)
        self.mappings = config['mappings']
        self.realm = config.get('realm', '')
        self.case_insensitive = config.get('case-insensitive', False)
        self.compiled_patterns = []
        
        for realm_name, pattern in sorted(self.mappings.items()):
            try:
                # Handle case when pattern is a list (config parser behavior)
                if isinstance(pattern, list):
                    if len(pattern) > 0:
                        pattern = pattern[0]  # Take first element
                    else:
                        raise RealmMappingError('Empty pattern list for realm {realm!r}'.format(realm=realm_name))
                flags = re.IGNORECASE if self.case_insensitive else 0
                compiled_pattern = re.compile(pattern, flags)
                self.compiled_patterns.append((realm_name, compiled_pattern))
            except re.error as e:
                raise RealmMappingError('Invalid regex pattern {pattern!r}: {error}'.format(
                    pattern=pattern, error=str(e)))

    def resolve(self, dn):
        """
        Resolve DN to realm using regex patterns.
        
        :param dn: Distinguished Name as string
        :return: Deferred firing tuple (app_marker, realm_name)
        """
        
        dn_to_check = dn
        
        for realm_name, pattern in self.compiled_patterns:
            match = pattern.match(dn_to_check)
            if match:
                try:
                    resolved_realm = realm_name.format(*match.groups(), **match.groupdict())
                    return defer.succeed((resolved_realm, resolved_realm))
                except (KeyError, IndexError):
                    return defer.succeed((realm_name, realm_name))
        
        return defer.succeed((self.realm, self.realm))

class AppCacheMappingStrategy(RealmMappingStrategy):
    """
    `app-cache` mapping strategy: Look up the app cache to find the correct realm.
    If you use this mapping strategy, make sure the app cache is enabled
    (see `[app-cache]`).

    Configuration:
        `mappings` is a subsection which maps app markers (as witnessed in LDAP search requests)
        to realm names.

        e.g.:

            [realm-mapping]
            strategy = app-cache

            [[mappings]]
            myapp-marker = myapp_realm
    """
    def __init__(self, factory, config):
        RealmMappingStrategy.__init__(self, factory, config)
        self.mappings = config['mappings']

    def resolve(self, dn):
        """
        Look up ``dn`` in the app cache, find the associated marker, look up the associated
        realm in the mapping config, return it.
        """
        marker = self.factory.app_cache.get_cached_marker(dn) # TODO: app cache might be None
        if marker is None:
            raise RealmMappingError('No entry in app cache for dn={dn!r}'.format(dn=dn))
        realm = self.mappings.get(marker)
        if realm is None:
            raise RealmMappingError('No mapping for marker={marker!r}'.format(marker=marker))
        return defer.succeed((marker, realm))

REALM_MAPPING_STRATEGIES = {
    'static': StaticMappingStrategy,
    'app-cache': AppCacheMappingStrategy,
    'regex': RegexMappingStrategy,
}
