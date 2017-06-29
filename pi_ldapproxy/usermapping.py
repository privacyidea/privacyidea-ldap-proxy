import re

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet import defer
from twisted.logger import Logger

log = Logger()

class UserMappingError(RuntimeError):
    pass

class UserMappingStrategy(object):
    """
    Base class for user mappers, which are used to determine the user's privacyIDEA login name
    from an incoming LDAP Bind Request's distinguished name.
    """
    def __init__(self, factory, config):
        """
        :param factory: `ProxyServerFactory` instance
        :param config: `[user-mapping]` section of the config file, as a dictionary
        """
        self.factory = factory
        self.config = config

    def resolve(self, dn):
        """
        Given the distinguished name, determine the login name or raise UserMappingError.
        :param dn: DN as string
        :return: A Deferred which fires the login name (as a string)
        """
        raise NotImplementedError()

class MatchMappingStrategy(UserMappingStrategy):
    """
    `match` mapping strategy: Expects a regular expression pattern which is matched against the incoming DN.
    It should contain one group which yields the username.

    Configuration:
        `pattern` contains the regular expression

    """
    def __init__(self, factory, config):
        UserMappingStrategy.__init__(self, factory, config)
        self.pattern = re.compile(config['pattern'], re.IGNORECASE)

    def resolve(self, dn):
        match = self.pattern.match(dn)
        if match is not None:
            return defer.succeed(match.group(1))
        else:
            raise UserMappingError(dn)

class LookupMappingStrategy(UserMappingStrategy):
    """
    `lookup` mapping strategy: Connect to the LDAP backend using the service account, find the
    corresponding entry and read a predefined attribute's value.

    Configuration:
        `attribute` contains the attribute name (e.g. sAMAccountName).

    """
    def __init__(self, factory, config):
        UserMappingStrategy.__init__(self, factory, config)
        self.attribute = config['attribute']

    @defer.inlineCallbacks
    def resolve(self, dn):
        """
        Given a distinguished name, return the login name to be used with privacyIDEA
        :param dn: distinguished name as string
        :return: Deferred that fires the login name
        """
        # Perform a LDAP bind, search for an object with the distinguished name *dn*
        client = yield self.factory.connect_service_account()
        entry = LDAPEntry(client, dn)
        try:
            results = yield entry.search('(objectClass=*)', scope=pureldap.LDAP_SCOPE_baseObject)
            # Assuming we found one, extract the login name attribute
            assert len(results) == 1
            if self.attribute not in results[0]:
                log.warn('Unknown lookup attribute: {attribute}', attribute=self.attribute)
                raise UserMappingError(dn)
            login_name_set = results[0][self.attribute]
            assert len(login_name_set) == 1
            (login_name,) = login_name_set
            defer.returnValue(login_name)
        except ldaperrors.LDAPNoSuchObject, e:
            # Apparently, the user could not be found. Raise the appropriate exception.
            raise UserMappingError(dn)
        finally:
            # TODO: Are there cases in which we can't unbind?
            yield client.unbind()

USER_MAPPING_STRATEGIES = {
    'match': MatchMappingStrategy,
    'lookup': LookupMappingStrategy,
}