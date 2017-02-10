#! /usr/bin/env python
import argparse
import json
import logging
import sys
import urllib
from cStringIO import StringIO
from functools import partial

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from twisted.web.client import Agent, FileBodyProducer, readBody
from twisted.web.http_headers import Headers

from pi_ldapproxy.bindcache import BindCache
from pi_ldapproxy.config import load_config
from pi_ldapproxy.usermapping import MAPPING_STRATEGIES

PROXIED_ENDPOINT_TEMPLATE = 'tcp:host={backend[host]}:port={backend[port]}'

class ProxyError(Exception):
    pass


class TwoFactorAuthenticationProxy(ProxyBase):
    def request_validate(self, url, user, realm, password):
        """
        Issue an HTTP request to authenticate an user with a password in a given
        realm using the specified privacyIDEA /validate/check endpoint.

        :param url: an HTTP or HTTPS url to the /validate/check endpoint
        :param user: username to authenticate
        :param realm: realm of the user, empty string for default realm
        :param password: password for authentication
        :return: A Twisted Deferred which yields a `twisted.web.client.Response` instance or fails.
        """
        body = urllib.urlencode({'user': user,
                                'realm': realm,
                                'pass': password})
        # TODO: HTTPS!
        # TODO: Is this really the preferred way to pass a string body?
        producer = FileBodyProducer(StringIO(body))
        d = self.factory.agent.request('POST',
                           url,
                           Headers({
                               'Content-Type': ['application/x-www-form-urlencoded'],
                               'User-Agent': ['LDAP Proxy']
                           }),
                           producer)
        return d

    @defer.inlineCallbacks
    def authenticate_bind_request(self, request):
        """
        Given a LDAP bind request, resolve the DN and redirect the request to privacyIDEA.
        :param request: An `pureldap.LDAPBindRequest` instance.
        :return: Deferred that fires a tuple ``(success, message)``, whereas ``success`` denotes whether privacyIDEA
        successfully validated the given password. If ``success`` is ``False``, ``message`` contains an error message.
        """
        user = yield self.factory.resolve_user(request.dn)
        log.msg('Resolved {!r} to {!r}'.format(request.dn, user))
        password = request.auth
        response = yield self.request_validate(self.factory.validate_url,
                                               user,
                                               self.factory.validate_realm,
                                               password)
        json_body = yield readBody(response)
        result = (False, '')
        if response.code == 200:
            body = json.loads(json_body)
            if body['result']['status']:
                if body['result']['value']:
                    result = (True, '')
                    # TODO: Is this the right place to bind the service user?
                    if self.factory.bind_service_account:
                        yield self.bind_service_account()
                else:
                    result = (False, 'Failed to authenticate.')
            else:
                result = (False, 'Failed to authenticate. privacyIDEA error.')
        else:
            result = (False, 'Failed to authenticate. Wrong HTTP response')
        defer.returnValue(result)

    def send_bind_response(self, result, request, reply):
        """
        Given a bind request, authentication result and a reply function, send a successful or a failed bind response.
        :param result: A tuple ``(success, message)``
        :param request: The corresponding ``LDAPBindRequest``
        :param reply: A function that expects a ``LDAPResult`` object
        :return: nothing
        """
        success, message = result
        if success:
            log.msg('Sending BindResponse "success"')
            self.factory.finalize_authentication(request.dn, request.auth)
            reply(pureldap.LDAPBindResponse(ldaperrors.Success.resultCode))
        else:
            log.msg('Sending BindResponse "invalid credentials": {}'.format(message))
            reply(pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode, errorMessage=message))

    def send_error_bind_response(self, failure, request, reply):
        """
        Given a failure and a reply function, log the failure and send a failed bind response.
        :param failure: A ``twisted.python.failure.Failure`` object
        :param request: The corresponding ``LDAPBindRequest``
        :param reply: A function that expects a ``LDAPResult`` object
        :return:
        """
        log.err(failure)
        # TODO: Is it right to send LDAPInvalidCredentials here?
        self.send_bind_response((False, 'LDAP Proxy failed.'), request, reply)

    @defer.inlineCallbacks
    def bind_service_account(self):
        """
        :return: A deferred that sends a bind request for the service account at `self.client`
        """
        log.msg('Binding service account ...')
        yield self.client.bind(self.factory.service_account_dn, self.factory.service_account_password)

    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Called by `ProxyBase` to handle an incoming request.
        :param request:
        :param controls:
        :param reply:
        :return:
        """
        if isinstance(request, pureldap.LDAPBindRequest):
            if request.dn == '':
                self.send_bind_response((False, 'Anonymous binds are not supported.'), request, reply)
                return None
            elif request.dn in self.factory.passthrough_binds:
                log.msg('BindRequest for {!r}, passing through ...'.format(request.dn))
                return request, controls
            elif self.factory.is_bind_cached(request.dn, request.auth):
                log.msg('Combination found in bind cache, authenticating as service user ...')
                # TODO: This is a shortcut - maybe do this differently
                request.dn = self.factory.service_account_dn
                request.auth = self.factory.service_account_password
                return request, controls
            else:
                log.msg("BindRequest for {!r} received, redirecting to privacyIDEA ...".format(request.dn))
                d = self.authenticate_bind_request(request)
                d.addCallback(self.send_bind_response, request, reply)
                d.addErrback(self.send_error_bind_response, request, reply)
                return None
        elif isinstance(request, pureldap.LDAPSearchRequest):
            # If the corresponding config option is not set, search requests are rejected.
            if not self.factory.allow_search:
                # TODO: Is that the right response?
                log.msg('Incoming search request, but configuration allows no search.')
                reply(pureldap.LDAPSearchResultDone(ldaperrors.LDAPInsufficientAccessRights.resultCode,
                                        errorMessage='LDAP Search disallowed according to the configuration.'))
                return None
            # Apparently, we can forward the search request.
            # Assuming `bind-service-account` is enabled and the privacyIDEA authentication was successful,
            # the service account is already authenticated for `self.client`.
            return request, controls
        else:
            log.msg("{!r} received, rejecting.".format(request.__class__.__name__))
            # TODO: Is that the right approach to reject (any) request?
            reply(pureldap.LDAPResult(ldaperrors.LDAPInsufficientAccessRights.resultCode,
                    errorMessage='Rejecting LDAP Search without successful privacyIDEA authentication'))
            return None

class ProxyServerFactory(protocol.ServerFactory):
    protocol = TwoFactorAuthenticationProxy

    def __init__(self, config):
        # NOTE: ServerFactory.__init__ does not exist?
        # Read configuration options.
        self.agent = Agent(reactor)
        self.use_tls = config['ldap-backend']['use-tls']
        if self.use_tls:
            # TODO: This seems to get lost if we use log.msg
            print 'LDAP over TLS is currently unsupported. Exiting.'
            sys.exit(1)

        self.proxied_endpoint_string = PROXIED_ENDPOINT_TEMPLATE.format(backend=config['ldap-backend'])
        self.validate_url = config['privacyidea']['endpoint']
        self.validate_realm = config['privacyidea']['realm']

        self.service_account_dn = config['service-account']['dn']
        self.service_account_password = config['service-account']['password']

        # We have to make a small workaround for configobj here: An empty config value
        # is interpreted as a list with one element, the empty string.
        self.passthrough_binds = config['ldap-proxy']['passthrough-binds']
        if len(self.passthrough_binds) == 1 and self.passthrough_binds[0]  == '':
            self.passthrough_binds = []
        log.msg('Passthrough DNs: {!r}'.format(self.passthrough_binds))

        self.allow_search = config['ldap-proxy']['allow-search']
        self.bind_service_account = config['ldap-proxy']['bind-service-account']

        mapping_strategy = MAPPING_STRATEGIES[config['user-mapping']['strategy']]
        log.msg('Using mapping strategy: {!r}'.format(mapping_strategy))

        self.user_mapper = mapping_strategy(self, config['user-mapping'])

        enable_bind_cache = config['bind-cache']['enabled']
        if enable_bind_cache:
            self.bind_cache = BindCache(config['bind-cache']['timeout'])
        else:
            self.bind_cache = None

    @defer.inlineCallbacks
    def connect_service_account(self):
        """
        Make a new connection to the LDAP backend server using the credentials of the service account
        :return: A Deferred that fires a `LDAPClient` instance
        """
        client = yield connectToLDAPEndpoint(reactor, self.proxied_endpoint_string, LDAPClient)
        if self.use_tls:
            client = yield client.startTLS()
        yield client.bind(self.service_account_dn, self.service_account_password)
        # TODO: What to do about an exception here?
        defer.returnValue(client)

    def resolve_user(self, dn):
        """
        Invoke the user mapper to find the username of the user identified by the DN *dn*.
        :param dn: LDAP distinguished name as string
        :return: a Deferred firing a string
        """
        return self.user_mapper.resolve(dn)

    def finalize_authentication(self, dn, password):
        """
        Called when a user was successfully authenticated by privacyIDEA. If the bind cache is enabled,
        add the corresponding credentials to the bind cache.
        :param dn: Distinguished Name as string
        :param password: Password as string
        """
        if self.bind_cache is not None:
            self.bind_cache.add_to_cache(dn, password)

    def is_bind_cached(self, dn, password):
        """
        Check whether the given credentials are found in the bind cache.
        If the bind cache is disabled, this always returns False.
        :param dn: Distinguished Name as string
        :param password: Password as string
        :return: a boolean
        """
        if self.bind_cache is not None:
            return self.bind_cache.is_cached(dn, password)
        else:
            return False

    def buildProtocol(self, addr):
        """
        called by Twisted for each new incoming connection.
        """
        proto = self.protocol()
        client_connector = partial(
                            connectToLDAPEndpoint,
                            reactor,
                            self.proxied_endpoint_string,
                            LDAPClient)
        proto.factory = self
        proto.clientConnector = client_connector
        proto.use_tls = self.use_tls
        return proto
