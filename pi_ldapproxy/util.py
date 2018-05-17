from OpenSSL.SSL import SSL_CB_HANDSHAKE_DONE
from twisted.internet._sslverify import OpenSSLCertificateOptions, ClientTLSOptions
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.web.client import _requireSSL
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer


@implementer(IOpenSSLClientConnectionCreator)
class DisabledVerificationClientTLSOptions(ClientTLSOptions):
    """
    ClientTLSOptions replacement that does not validate the hostname certificate at all, i.e.
    neither checks if the certificate matches the hostname nor the certificate's trust chain.
    """
    def _identityVerifyingInfoCallback(self, connection, where, ret):
        """
        In case *where* indicates that the SSL handshake has been done,
        this does nothing (as opposed to ClientTLSOptions._identityVerifyingInfoCallback,
        which would validate the certificate). In all other cases,
        the superclass method is called.
        """
        if where & SSL_CB_HANDSHAKE_DONE:
            # ClientTLSOptions._identityVerifyingInfoCallback would validate the certificate
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
