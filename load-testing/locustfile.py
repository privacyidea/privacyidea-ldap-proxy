import random

import ldap3
import time

from locust import TaskSet
from locust import events, Locust
from locust import task

USER_DNS = 'uid=user{:03},cn=users,dc=test,dc=intranet'
USER_PASSWORDS = 'pin{:03}'

USERS = dict((USER_DNS.format(i), USER_PASSWORDS.format(i)) for i in range(1000))

class LDAPConnection(ldap3.Connection):
    def bind(self, *args, **kwargs):
        start_time = time.time()
        result = ldap3.Connection.bind(self, *args, **kwargs)
        total_time = int((time.time() - start_time) * 1000)
        if result:
            events.request_success.fire(request_type='ldap-bind', name=self.user, response_time=total_time,
                                        response_length=0)
        else:
            events.request_failure.fire(request_type='ldap-bind', name=self.user, response_time=total_time,
                                        exception="{result}: {message}".format(**self.result))

class LDAPLocust(Locust):
    def __init__(self, *args, **kwargs):
        super(LDAPLocust, self).__init__(*args, **kwargs)
        dn = random.choice(list(USERS.keys()))
        pin = USERS[dn]
        self.client = LDAPConnection(self.host,
                                     user=dn,
                                     password=pin)

class ApiUser(LDAPLocust):
    min_wait = 100
    max_wait = 1000

    class task_set(TaskSet):
        @task
        def bind(self):
            try:
                self.client.bind()
            finally:
                self.client.unbind()
