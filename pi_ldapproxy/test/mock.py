import json

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
        body = json.dumps({
            'result': {
                'status': True,
                'value': result,
            },
        })
        headers = Headers(SUCCESSFUL_HEADERS)
        response = MockResponse(b'HTTP/1.1', 200, 'OK', headers, body)
        return response

    def authenticate(self, url, user, realm, password):
        result = self.is_password_correct(user, realm, password)
        return defer.succeed(self.build_response(result))

    def inject(self, server):
        server.request_validate = self.authenticate