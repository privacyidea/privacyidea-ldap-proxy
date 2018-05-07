from OpenSSL.SSL import SSL_CB_HANDSHAKE_DONE
from twisted.internet._sslverify import OpenSSLCertificateOptions, ClientTLSOptions
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.web.client import _requireSSL
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer


@implementer(IOpenSSLClientConnectionCreator)
class DisabledVerificationClientTLSOptions(ClientTLSOptions):
    def _identityVerifyingInfoCallback(self, connection, where, ret):
        """
        Do not check the remote hostname
        """
        if where & SSL_CB_HANDSHAKE_DONE:
            # ClientTLSOptions._identityVerifyingInfoCallback will validate the certificate
            # in that case. Instead, we just do nothing.
            pass
        else:
            return ClientTLSOptions._identityVerifyingInfoCallback(self, connection, where, ret)


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
        return DisabledVerificationClientTLSOptions(hostname, certificate_options.getContext())
