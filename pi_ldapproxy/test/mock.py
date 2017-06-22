import json

import httplib
from ldaptor import testutil
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from twisted.internet import defer
from twisted.web.client import Response
from twisted.web.http_headers import Headers

SUCCESSFUL_HEADERS = {
    'Date': ['Fri, 24 Feb 2017 09:16:29 GMT'],
    'Server': ['privacyIDEA Mock'],
    'Cache-Control': ['no-cache'],
    'Content-Type': ['application/json'],
}

class MockResponse(Response):
    def __init__(self, version, code, phrase, headers, body):
        headers.addRawHeader('Content-Length', [str(len(body))])
        Response.__init__(self, version, code, phrase, headers, None)
        self.body = body

    def deliverBody(self, protocol):
        protocol.deferred.callback(self.body)


class MockPrivacyIDEA(object):
    def __init__(self, credentials):
        self.credentials = credentials
        self.status = True
        self.response_code = 200
        self.authentication_requests = []

    def is_password_correct(self, user, realm, password):
        key = '{}@{}'.format(user, realm)
        if key in self.credentials:
            expected = self.credentials[key]
            if isinstance(expected, list):
                expected_password = expected[0]
                if password == expected_password:
                    expected.pop()
                    return True
                else:
                    return False
            else:
                return password == expected
        else:
            return False

    def build_response(self, result):
        data = {
            'result': {
                'status': self.status,
            },
        }
        if self.status:
            data['result']['value'] = result
        body = json.dumps(data)
        headers = Headers(SUCCESSFUL_HEADERS)
        response = MockResponse(b'HTTP/1.1', self.response_code, httplib.responses[self.response_code], headers, body)
        return response

    def authenticate(self, url, user, realm, password):
        result = self.is_password_correct(user, realm, password)
        self.authentication_requests.append((user, realm, password, result))
        return defer.succeed(self.build_response(result))

    def inject(self, server):
        server.request_validate = self.authenticate


class MockLDAPClient(testutil.LDAPClientTestDriver):
    def bind(self, dn, auth):
        self.send(pureldap.LDAPBindRequest(dn=dn, auth=auth))

