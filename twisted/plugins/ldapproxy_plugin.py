import sys

from zope.interface import implementer

from twisted.python import usage, log
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet

from pi_ldapproxy.config import load_config
from pi_ldapproxy.proxy import ProxyServerFactory


class Options(usage.Options):
    optParameters = [["config", "c", None, "Configuration file"]]


@implementer(IServiceMaker, IPlugin)
class ProxyServiceMaker(object):
    tapname = "ldap-proxy"
    description = "LDAP Proxy"
    options = Options

    def makeService(self, options):
        if options['config'] is None:
            print 'You need to specify a configuration file via `twistd ldap-proxy -c config.ini`.'
            sys.exit(1)

        config = load_config(options['config'])
        factory = ProxyServerFactory(config)

        proxy_port = config['ldap-proxy']['port']
        proxy_hostname = config['ldap-proxy']['hostname']
        log.msg('Listening on {}:{} ...'.format(proxy_hostname, proxy_port))
        return internet.TCPServer(proxy_port,
                                  factory,
                                  interface=proxy_hostname)


serviceMaker = ProxyServiceMaker()