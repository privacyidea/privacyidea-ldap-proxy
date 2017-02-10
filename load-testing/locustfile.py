import ldap3
import time

from locust import TaskSet
from locust import events, Locust
from locust import task

USER_DN = 'cn=test,cn=user,dc=test,dc=local'
USER_PASSWORD = 'test'

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

    #def search(self, *args, **kwargs):
    #    start_time = time.time()
    #    result = ldap3.Connection.search(self, *args, **kwargs)
    #    total_time = int((time.time() - start_time) * 1000)
    #    if len(self.response) > 0:
    #        event = events.request_success
    #    else:
    #        event = events.request_failure
    #    event.fire(request_type='ldap-search', name=self.user, response_time=total_time, response_length=0)

class LDAPLocust(Locust):
    def __init__(self, *args, **kwargs):
        super(LDAPLocust, self).__init__(*args, **kwargs)
        self.client = LDAPConnection(self.host,
                                     user=USER_DN,
                                     password=USER_PASSWORD)

class ApiUser(LDAPLocust):
    min_wait = 100
    max_wait = 1000

    class task_set(TaskSet):
        @task
        def bind(self):
            self.client.bind()
