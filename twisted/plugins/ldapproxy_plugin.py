import sys

from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from zope.interface import implementer

from twisted.python import usage, log
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet

from pi_ldapproxy.config import load_config
from pi_ldapproxy.proxy import ProxyServerFactory


class Options(usage.Options):
    #: The configuration file (which is mandatory) is passed as a parameter.
    #: It might be desirable to use a positional argument instead.
    optParameters = [["config", "c", None, "Configuration file"]]


@implementer(IServiceMaker, IPlugin)
class ProxyServiceMaker(object):
    tapname = "ldap-proxy"
    description = "privacyIDEA LDAP Proxy"
    options = Options

    def makeService(self, options):
        """
        Called by Twisted after having parsed the command-line options.
        :param options: ``usage.Options`` instance
        :return: the server instance
        """
        # Configuration is mandatory
        if options['config'] is None:
            print 'You need to specify a configuration file via `twistd ldap-proxy -c config.ini`.'
            sys.exit(1)

        config = load_config(options['config'])
        factory = ProxyServerFactory(config)

        endpoint_string = serverFromString(reactor, config['ldap-proxy']['endpoint'])
        return internet.StreamServerEndpointService(endpoint_string, factory)


serviceMaker = ProxyServiceMaker()