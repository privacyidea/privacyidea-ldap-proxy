from twisted.internet._sslverify import OpenSSLCertificateOptions, ClientTLSOptions
from twisted.web.client import _requireSSL
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer


@implementer(IPolicyForHTTPS)
class DisabledVerificationPolicyForHTTPS(object):
    """ HTTPS policy that does not check the certificate hostname """
    @_requireSSL
    def creatorForNetloc(self, hostname, port):
        hostname = hostname.decode("ascii")
        certificate_options = OpenSSLCertificateOptions(
            trustRoot=None,
            acceptableProtocols=None,
        )
        return ClientTLSOptions(hostname, certificate_options.getContext())
