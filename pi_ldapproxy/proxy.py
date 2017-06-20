#! /usr/bin/env python
import argparse
import json
import sys
import re
import urllib
from cStringIO import StringIO
from functools import partial

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.logger import Logger
from twisted.web.client import Agent, FileBodyProducer, readBody
from twisted.web.http_headers import Headers

from pi_ldapproxy.bindcache import BindCache
from pi_ldapproxy.config import load_config
from pi_ldapproxy.preamblecache import PreambleCache
from pi_ldapproxy.realmmapping import detect_login_preamble
from pi_ldapproxy.usermapping import MAPPING_STRATEGIES, UserMappingError

log = Logger()

class ProxyError(Exception):
    pass

DN_BLACKLIST = map(re.compile, ['^dn=uid='])
VALIDATE_URL_TEMPLATE = '{}validate/check'

class TwoFactorAuthenticationProxy(ProxyBase):
    #: Specifies whether we have sent a bind request to the LDAP backend at some point
    bound = False

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
        # TODO: Is this really the preferred way to pass a string body?
        producer = FileBodyProducer(StringIO(body))
        d = self.factory.agent.request('POST',
                           url,
                           Headers({
                               'Content-Type': ['application/x-www-form-urlencoded'],
                               'User-Agent': ['privacyIDEA LDAP Proxy']
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
        result = (False, '')
        try:
            user = yield self.factory.resolve_user(request.dn)
        except UserMappingError:
            # User could not be found
            log.info('Could not resolve {dn!r}', dn=request.dn)
            result = (False, 'Invalid user.')
        else:
            log.info('Resolved {dn!r} to {user!r}', dn=request.dn, user=user)
            password = request.auth
            response = yield self.request_validate(self.factory.validate_url,
                                                   user,
                                                   self.factory.validate_realm,
                                                   password)
            json_body = yield readBody(response)
            if response.code == 200:
                body = json.loads(json_body)
                if body['result']['status']:
                    if body['result']['value']:
                        result = (True, '')
                        # TODO: Is this the right place to bind the service user?
                        if self.factory.bind_service_account:
                            yield self.bind_service_account()
                            self.bound = True
                    else:
                        result = (False, 'Failed to authenticate.')
                else:
                    result = (False, 'Failed to authenticate. privacyIDEA error.')
            else:
                result = (False, 'Failed to authenticate. Wrong HTTP response ({})'.format(response.code))
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
            log.info('Sending BindResponse "success"')
            self.factory.finalize_authentication(request.dn, request.auth)
            reply(pureldap.LDAPBindResponse(ldaperrors.Success.resultCode))
        else:
            log.info('Sending BindResponse "invalid credentials": {message}', message=message)
            reply(pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode, errorMessage=message))

    def send_error_bind_response(self, failure, request, reply):
        """
        Given a failure and a reply function, log the failure and send a failed bind response.
        :param failure: A ``twisted.python.failure.Failure`` object
        :param request: The corresponding ``LDAPBindRequest``
        :param reply: A function that expects a ``LDAPResult`` object
        :return:
        """
        log.failure("Could not bind", failure)
        # TODO: Is it right to send LDAPInvalidCredentials here?
        self.send_bind_response((False, 'LDAP Proxy failed.'), request, reply)

    @defer.inlineCallbacks
    def bind_service_account(self):
        """
        :return: A deferred that sends a bind request for the service account at `self.client`
        """
        log.info('Binding service account ...')
        yield self.client.bind(self.factory.service_account_dn, self.factory.service_account_password)

    def handleProxiedResponse(self, response, request, controls):
        """
        Called by `ProxyBase` to handle the response of an incoming request.
        :param response:
        :param request:
        :param controls:
        :return:
        """
        # Try to detect login preamble
        if isinstance(request, pureldap.LDAPSearchRequest):
            # TODO: Read attribute and value prefix from config
            # TODO: Check that this is connection is bound to the service account?
            self.factory.process_search_response(request, response)
        return response

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
            elif self.factory.is_dn_blacklisted(request.dn):
                self.send_bind_response((False, 'DN is blacklisted.'), request, reply)
                return None
            elif request.dn in self.factory.passthrough_binds:
                log.info('BindRequest for {dn!r}, passing through ...', dn=request.dn)
                self.bound = True
                return request, controls
            elif self.factory.is_bind_cached(request.dn, request.auth):
                log.info('Combination found in bind cache, authenticating as service user ...')
                # TODO: This is a shortcut - maybe do this differently
                request.dn = self.factory.service_account_dn
                request.auth = self.factory.service_account_password
                return request, controls
            else:
                log.info("BindRequest for {dn!r} received, redirecting to privacyIDEA ...", dn=request.dn)
                d = self.authenticate_bind_request(request)
                d.addCallback(self.send_bind_response, request, reply)
                d.addErrback(self.send_error_bind_response, request, reply)
                return None
        elif isinstance(request, pureldap.LDAPSearchRequest):
            # If the corresponding config option is not set, search requests are rejected.
            if not self.factory.allow_search:
                # TODO: Is that the right response?
                log.info('Incoming search request, but configuration allows no search.')
                reply(pureldap.LDAPSearchResultDone(ldaperrors.LDAPInsufficientAccessRights.resultCode,
                                        errorMessage='LDAP Search disallowed according to the configuration.'))
                return None
            # Apparently, we can forward the search request.
            # Assuming `bind-service-account` is enabled and the privacyIDEA authentication was successful,
            # the service account is already authenticated for `self.client`.
            return request, controls
        elif isinstance(request, pureldap.LDAPUnbindRequest) and self.bound:
            # If we have sent a bind request to the LDAP backend in the past, we will forward
            # the incoming unbind request.
            # TODO: What if we receive multiple unbind requests?
            return request, controls
        else:
            log.info("{class_!r} received, rejecting.", class_=request.__class__.__name__)
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
            # TODO: This seems to get lost if we use log.info
            print 'LDAP over TLS is currently unsupported. Exiting.'
            sys.exit(1)

        self.proxied_endpoint_string = config['ldap-backend']['endpoint']
        self.privacyidea_instance = config['privacyidea']['instance']
        # Construct the validate url from the instance location
        if self.privacyidea_instance[-1] != '/':
            self.privacyidea_instance += '/'
        self.validate_url = VALIDATE_URL_TEMPLATE.format(self.privacyidea_instance)
        self.validate_realm = config['privacyidea']['realm']

        self.service_account_dn = config['service-account']['dn']
        self.service_account_password = config['service-account']['password']

        # We have to make a small workaround for configobj here: An empty config value
        # is interpreted as a list with one element, the empty string.
        self.passthrough_binds = config['ldap-proxy']['passthrough-binds']
        if len(self.passthrough_binds) == 1 and self.passthrough_binds[0]  == '':
            self.passthrough_binds = []
        log.info('Passthrough DNs: {binds!r}', binds=self.passthrough_binds)

        self.allow_search = config['ldap-proxy']['allow-search']
        self.bind_service_account = config['ldap-proxy']['bind-service-account']

        mapping_strategy = MAPPING_STRATEGIES[config['user-mapping']['strategy']]
        log.info('Using mapping strategy: {strategy!r}', strategy=mapping_strategy)

        self.user_mapper = mapping_strategy(self, config['user-mapping'])

        enable_bind_cache = config['bind-cache']['enabled']
        if enable_bind_cache:
            self.bind_cache = BindCache(config['bind-cache']['timeout'])
        else:
            self.bind_cache = None

        enable_preamble_cache = config['preamble-cache']['enabled']
        if enable_preamble_cache:
            self.preamble_cache = PreambleCache(config['preamble-cache']['timeout'])
        else:
            self.preamble_cache = None
        self.preamble_cache_attribute = config['preamble-cache']['attribute']
        self.preamble_cache_value_prefix = config['preamble-cache']['value-prefix']

        if config['ldap-backend']['test-connection']:
            self.test_connection()

    @defer.inlineCallbacks
    def connect_service_account(self):
        """
        Make a new connection to the LDAP backend server using the credentials of the service account
        :return: A Deferred that fires a `LDAPClient` instance
        """
        client = yield connectToLDAPEndpoint(reactor, self.proxied_endpoint_string, LDAPClient)
        if self.use_tls:
            client = yield client.startTLS()
        try:
            yield client.bind(self.service_account_dn, self.service_account_password)
        except ldaperrors.LDAPException, e:
            # Call unbind() here if an exception occurs: Otherwise, Twisted will keep the file open
            # and slowly run out of open files.
            yield client.unbind()
            raise e
        defer.returnValue(client)

    def resolve_user(self, dn):
        """
        Invoke the user mapper to find the username of the user identified by the DN *dn*.
        :param dn: LDAP distinguished name as string
        :return: a Deferred firing a string (or raising a UserMappingError)
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

    def process_search_response(self, request, response):
        if self.preamble_cache is not None:
            result = detect_login_preamble(request,
                                           response,
                                           self.preamble_cache_attribute,
                                           self.preamble_cache_value_prefix)
            if result is not None:
                dn, marker = result
                log.info('Detected login preamble: dn={dn!r}, marker={marker!r}'.format(dn=dn, marker=marker))
                self.preamble_cache.add_to_cache(dn, marker)

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

    def is_dn_blacklisted(self, dn):
        """
        Check whether the given distinguished name is part of our blacklist
        :param dn: Distinguished Name as string
        :return: a boolean
        """
        return any(pattern.match(dn) for pattern in DN_BLACKLIST)

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

    @defer.inlineCallbacks
    def test_connection(self):
        """
        Connect to the LDAP backend using an anonymous bind and unbind after that.
        :return: a Deferred that fires True or False
        """
        try:
            client = yield connectToLDAPEndpoint(reactor, self.proxied_endpoint_string, LDAPClient)
            yield client.bind()
            yield client.unbind()
            log.info('Successfully tested the connection to the LDAP backend using an anonymous bind')
            defer.returnValue(True)
        except Exception, e:
            log.failure('Could not connect to LDAP backend', exception=e)
            defer.returnValue(False)