from ldaptor.protocols.pureldap import LDAPFilter_and, LDAPFilter_or, LDAPFilter_equalityMatch, LDAPSearchRequest, \
    LDAPSearchResultEntry
from twisted.logger import Logger

log = Logger()


def find_app_marker(filter, attribute='objectclass', value_prefix='App-'):
    """
    Given an ldaptor filter, try to extract an app marker, i.e. find
    a marker such that the filter contains an expression (<attribute>=<value_prefix><marker>),
    e.g. (objectclass=App-ownCloud).
    It may be nested in &() and |() expressions.
    :param filter: ldaptor filter
    :param attribute: attribute name whose value contains the app marker
    :param value_prefix: prefix of the app marker
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
        if filter.attributeDesc.value == attribute:
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
        # TODO: This will be called multiple times for the same search request!
        # i.e. we do not notice if the response has >1 entries
        if marker is not None and isinstance(response, LDAPSearchResultEntry):
            return (response.objectName, marker)
    return None
