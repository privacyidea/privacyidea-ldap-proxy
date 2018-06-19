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
from twisted.internet.ssl import Certificate
from twisted.python.filepath import FilePath
from twisted.web.client import Agent, FileBodyProducer, readBody, BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers

from pi_ldapproxy.bindcache import BindCache
from pi_ldapproxy.config import load_config
from pi_ldapproxy.appcache import AppCache
from pi_ldapproxy.realmmapping import detect_login_preamble, REALM_MAPPING_STRATEGIES, RealmMappingError
from pi_ldapproxy.usermapping import USER_MAPPING_STRATEGIES, UserMappingError
from pi_ldapproxy.util import DisabledVerificationPolicyForHTTPS

log = Logger()

class ProxyError(Exception):
    pass

DN_BLACKLIST = map(re.compile, ['^dn=uid='])
VALIDATE_URL_TEMPLATE = '{}validate/check'

class TwoFactorAuthenticationProxy(ProxyBase):
    def __init__(self):
        ProxyBase.__init__(self)
        # Set the state initially
        self.reset_state()

    def _connectedToProxiedServer(self, proto):
        """
        Workaround for ldaptor bug #105. In case the application has disconnected before
        the connection to the LDAP backend has been established, we want to close the
        connection to the LDAP backend. This works around the problem that health checks
        may result in leftover sockets.
        """
        if not self.connected:
            log.info('Client has disconnected already, closing connection to LDAP backend ...')
            proto.transport.loseConnection()
            self.queuedRequests = []
        else:
            ProxyBase._connectedToProxiedServer(self, proto)

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
                               'User-Agent': ['privacyIDEA-LDAP-Proxy']
                           }),
                           producer)
        return d

    @defer.inlineCallbacks
    def authenticate_bind_request(self, request):
        """
        Given a LDAP bind request:
         * Check if it is contained in the bind cache.
            If yes: Return success and bind the service account.
         * If not: resolve the DN and redirect the request to privacyIDEA.
        :param request: An `pureldap.LDAPBindRequest` instance.
        :return: Deferred that fires a tuple ``(success, message)``, whereas ``success`` denotes whether privacyIDEA
        successfully validated the given password. If ``success`` is ``False``, ``message`` contains an error message.
        """
        #: This 2-tuple has the following semantics:
        #: If the first element is True, authentication has succeeded! The second element then
        #: contains the app marker as a string.
        #: If the first element is False, authentication has failed. The second element then contains
        #: the error message.
        result = (False, '')
        try:
            app_marker, realm = yield self.factory.resolve_realm(request.dn)
            user = yield self.factory.resolve_user(request.dn)
        except UserMappingError:
            # User could not be found
            log.info('Could not resolve {dn!r} to user', dn=request.dn)
            result = (False, 'Invalid user.')
        except RealmMappingError, e:
            # Realm could not be mapped
            log.info('Could not resolve {dn!r} to realm: {message!r}', dn=request.dn, message=e.message)
            # TODO: too much information revealed?
            result = (False, 'Could not determine realm.')
        else:
            log.info('Resolved {dn!r} to {user!r}@{realm!r} ({marker!r})',
                     dn=request.dn, user=user, realm=realm, marker=app_marker)
            password = request.auth
            if self.factory.is_bind_cached(request.dn, app_marker, request.auth):
                log.info('Combination found in bind cache!')
                result = (True, app_marker)
            else:
                response = yield self.request_validate(self.factory.validate_url,
                                                       user,
                                                       realm,
                                                       password)
                json_body = yield readBody(response)
                if response.code == 200:
                    body = json.loads(json_body)
                    if body['result']['status']:
                        if body['result']['value']:
                            result = (True, app_marker)
                        else:
                            result = (False, 'Failed to authenticate.')
                    else:
                        result = (False, 'Failed to authenticate. privacyIDEA error.')
                else:
                    result = (False, 'Failed to authenticate. Wrong HTTP response ({})'.format(response.code))
        # TODO: Is this the right place to bind the service user?
        # (check that result[0] is actually True and not just truthy)
        if result[0] is True and self.factory.bind_service_account:
            log.info('Successful authentication, authenticating as service user ...')
            # Reset value in case the connection is re-used
            self.forwarded_passthrough_bind = False
            yield self.bind_service_account()
        defer.returnValue(result)

    def send_bind_response(self, result, request, reply):
        """
        Given a bind request, authentication result and a reply function, send a successful or a failed bind response.
        :param result: A tuple ``(success, message/app marker)``
        :param request: The corresponding ``LDAPBindRequest``
        :param reply: A function that expects a ``LDAPResult`` object
        :return: nothing
        """
        success, message = result
        if success:
            log.info('Sending BindResponse "success"')
            app_marker = message
            self.factory.finalize_authentication(request.dn, app_marker, request.auth)
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
        try:
            # Try to detect login preamble
            if isinstance(request, pureldap.LDAPSearchRequest):
                # If we are sending back a search result entry, we just save it for preamble detection
                # and count the total number of search result entries.
                if isinstance(response, pureldap.LDAPSearchResultEntry):
                    self.last_search_response_entry = response
                    self.search_response_entries += 1
                elif isinstance(response, pureldap.LDAPSearchResultDone):
                    # only check for preambles if we returned exactly one search result entry
                    # and if this connection was established in the context of a passthrough bind
                    # (i.e. an app service account)
                    if self.search_response_entries == 1 and self.forwarded_passthrough_bind:
                        self.factory.process_search_response(request, self.last_search_response_entry)
                    # reset counter and storage
                    self.search_response_entries = 0
                    self.last_search_response_entry = None
                elif isinstance(response, pureldap.LDAPSearchResultReference):
                    if self.factory.ignore_search_result_references:
                        log.info('Ignoring LDAP SEARCH result reference ...')
                        return None
                    else:
                        log.warn('Possibly sending an invalid LDAP SEARCH result reference, '
                                 'check the ignore-search-result-reference config option for more details.')
        except Exception, e:
            log.failure("Unhandled error in handleProxiedResponse: {e}", e=e)
            raise
        return response

    def reset_state(self):
        """
        Reset the internal state of the connection to its initial state.
        This is used in case a LDAP conneciton is reused, i.e. more than
        one bind request is received:
        """
        #: Specifies whether we have received a Bind Request at some point
        self.received_bind_request = False
        #: Specifies whether we forwarded a Bind Request to the LDAP backend because the
        #: DN was found in passthrough_binds.
        self.forwarded_passthrough_bind = False
        #: If we are currently processing a search request, this stores the last entry
        #: sent during its response. Otherwise, it is None.
        self.last_search_response_entry = None
        #: If we are currently processing a search request, this stores the total number of
        #: entries sent during its response.
        # Why do we have these two attributes here? For preamble detection, we need to make sure
        # that the search request returns only one entry. To achieve that, we could store all entries
        # in a list. However, this introduces unnecessary space overhead (e.g. if the app queries
        # all users). Thus, we only store the last entry and the total entry count.
        self.search_response_entries = 0

    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Called by `ProxyBase` to handle an incoming request.
        :param request:
        :param controls:
        :param reply:
        :return:
        """
        if isinstance(request, pureldap.LDAPBindRequest):
            if self.received_bind_request:
                # We have already received a bind request in this connection!
                if self.factory.allow_connection_reuse:
                    # We need to reset the state before further processing the request
                    log.info('Reusing LDAP connection, resetting state ...')
                    self.reset_state()
                else:
                    log.warn('Rejected a second bind request in the same connection. '
                             'Please check the `allow-connection-reuse` config option.')
                    self.send_bind_response((False, 'Reusing connections is disabled.'), request, reply)
                    return None
            self.received_bind_request = True
            if request.dn == '':
                if self.factory.forward_anonymous_binds:
                    return request, controls
                else:
                    self.send_bind_response((False, 'Anonymous binds are not supported.'), request, reply)
                    return None
            elif self.factory.is_dn_blacklisted(request.dn):
                self.send_bind_response((False, 'DN is blacklisted.'), request, reply)
                return None
            elif request.dn in self.factory.passthrough_binds:
                log.info('BindRequest for {dn!r}, passing through ...', dn=request.dn)
                self.forwarded_passthrough_bind = True
                return request, controls
            else:
                log.info("BindRequest for {dn!r} received ...", dn=request.dn)
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
        elif isinstance(request, pureldap.LDAPUnbindRequest):
            # We just forward any Unbind Request, regardless of whether we have sent a Bind Request to
            # the LDAP backend earlier.
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
        if config['privacyidea']['verify']:
            if config['privacyidea']['certificate']:
                certificate_path = config['privacyidea']['certificate']
                certificate = Certificate.loadPEM(FilePath(certificate_path).getContent())
                log.info('privacyIDEA HTTPS certificate will be checked against {certificate!r} from {path!r}',
                         certificate=certificate, path=certificate_path)
            else:
                certificate = None
                log.info('privacyIDEA HTTPS certificate will be checked against system certificate store')
            https_policy = BrowserLikePolicyForHTTPS(certificate)
        else:
            log.warn('privacyIDEA HTTPS certificate will NOT be checked!')
            https_policy = DisabledVerificationPolicyForHTTPS()
        self.agent = Agent(reactor, https_policy)
        if config['ldap-backend']['use-tls']:
            # TODO: This seems to get lost if we use log.info
            log.warn('The use-tls config option is deprecated and will be ignored.')

        self.proxied_endpoint_string = config['ldap-backend']['endpoint']
        self.privacyidea_instance = config['privacyidea']['instance']
        # Construct the validate url from the instance location
        if self.privacyidea_instance[-1] != '/':
            self.privacyidea_instance += '/'
        self.validate_url = VALIDATE_URL_TEMPLATE.format(self.privacyidea_instance)

        self.service_account_dn = config['service-account']['dn']
        self.service_account_password = config['service-account']['password']

        # We have to make a small workaround for configobj here: An empty config value
        # is interpreted as a list with one element, the empty string.
        self.passthrough_binds = config['ldap-proxy']['passthrough-binds']
        if len(self.passthrough_binds) == 1 and self.passthrough_binds[0]  == '':
            self.passthrough_binds = []
        log.info('Passthrough DNs: {binds!r}', binds=self.passthrough_binds)

        self.forward_anonymous_binds = config['ldap-proxy']['forward-anonymous-binds']

        self.allow_search = config['ldap-proxy']['allow-search']
        self.bind_service_account = config['ldap-proxy']['bind-service-account']
        self.allow_connection_reuse = config['ldap-proxy']['allow-connection-reuse']
        self.ignore_search_result_references = config['ldap-proxy']['ignore-search-result-references']

        user_mapping_strategy = USER_MAPPING_STRATEGIES[config['user-mapping']['strategy']]
        log.info('Using user mapping strategy: {strategy!r}', strategy=user_mapping_strategy)

        self.user_mapper = user_mapping_strategy(self, config['user-mapping'])

        realm_mapping_strategy = REALM_MAPPING_STRATEGIES[config['realm-mapping']['strategy']]
        log.info('Using realm mapping strategy: {strategy!r}', strategy=realm_mapping_strategy)

        self.realm_mapper = realm_mapping_strategy(self, config['realm-mapping'])

        enable_bind_cache = config['bind-cache']['enabled']
        if enable_bind_cache:
            self.bind_cache = BindCache(config['bind-cache']['timeout'])
        else:
            self.bind_cache = None

        enable_app_cache = config['app-cache']['enabled']
        if enable_app_cache:
            self.app_cache = AppCache(config['app-cache']['timeout'], config['app-cache']['case-insensitive'])
        else:
            self.app_cache = None
        self.app_cache_attribute = config['app-cache']['attribute']
        self.app_cache_value_prefix = config['app-cache']['value-prefix']

        if config['ldap-backend']['test-connection']:
            self.test_connection()

    @defer.inlineCallbacks
    def connect_service_account(self):
        """
        Make a new connection to the LDAP backend server using the credentials of the service account
        :return: A Deferred that fires a `LDAPClient` instance
        """
        client = yield connectToLDAPEndpoint(reactor, self.proxied_endpoint_string, LDAPClient)
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

    def resolve_realm(self, dn):
        """
        Invoke the realm mapper to find the realm of the user identified by the DN *dn*.
        :param dn: LDAP distinguished name as string
        :return: a Deferred firing a string (or raising a RealmMappingError)
        """
        return self.realm_mapper.resolve(dn)

    def finalize_authentication(self, dn, app_marker, password):
        """
        Called when a user was successfully authenticated by privacyIDEA. If the bind cache is enabled,
        add the corresponding credentials to the bind cache.
        :param dn: Distinguished Name as string
        :param app_marker: app marker
        :param password: Password as string
        """
        if self.bind_cache is not None:
            self.bind_cache.add_to_cache(dn, app_marker, password)

    def process_search_response(self, request, response):
        """
        Called when ``response`` is sent in response to ``request``. If the app cache is enabled,
        ``detect_login_preamble`` is invoked in order to detect a login preamble. If one was detected,
        the corresponding entry is added to the app cache.
        :param request: LDAPSearchRequest
        :param response: LDAPSearchResultEntry or LDAPSearchResultDone
        :return:
        """
        if self.app_cache is not None:
            result = detect_login_preamble(request,
                                           response,
                                           self.app_cache_attribute,
                                           self.app_cache_value_prefix)
            if result is not None:
                dn, marker = result
                self.app_cache.add_to_cache(dn, marker)

    def is_bind_cached(self, dn, app_marker, password):
        """
        Check whether the given credentials are found in the bind cache.
        If the bind cache is disabled, this always returns False.
        :param dn: Distinguished Name as string
        :param app_marker: App marker as string
        :param password: Password as string
        :return: a boolean
        """
        if self.bind_cache is not None:
            return self.bind_cache.is_cached(dn, app_marker, password)
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
        return proto

    @defer.inlineCallbacks
    def test_connection(self):
        """
        Connect to the LDAP backend using an anonymous bind and unbind after that.
        :return: a Deferred that fires True or False
        """
        try:
            client = yield self.connect_service_account()
            yield client.unbind()
            log.info('Successfully tested the connection to the LDAP backend using the service account')
            defer.returnValue(True)
        except Exception, e:
            log.failure('Could not connect to LDAP backend', exception=e)
            defer.returnValue(False)