from ldaptor.protocols.pureldap import LDAPFilter_and, LDAPFilter_or, LDAPFilter_equalityMatch, LDAPSearchRequest, \
    LDAPSearchResultEntry
from twisted.internet import defer
from twisted.logger import Logger

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
        if filter.attributeDesc.value.lower() == attribute.lower():
            value = filter.assertionValue.value
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
}