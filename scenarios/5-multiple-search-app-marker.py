"""
Scenario 5) App uses a service account to look up user's DN. The search request's filter contains a marker which the
LDAP proxy uses to identify the requesting application.
Afterwards, the user sends *two* bind and search requests.

Given a username, the app uses a service account to find the user's DN. For that, it performs an LDAP bind followed
by an LDAP search. After that, it issues a bind on behalf of the user and uses an LDAP search under the user's
context to retrieve profile information of the user. This is done twice during a 3-second timeframe.

This will only work if the LDAP proxy caches bind requests.
We cannot determine whether realm mapping is carried out correctly on the client side.
"""
from pprint import pprint

import ldap3
import configobj
import time

from common import lookup_user

def perform_login_search(dn, password, ldap_server):
    conn = ldap3.Connection(ldap_server, user=dn, password=password)
    print('Bind with password {!r} ...'.format(password), end=' ')
    result = conn.bind()
    if result:
        print('Successful bind!')
        # Fetch user information
        conn.search(dn, '(objectClass=*)', attributes=ldap3.ALL_ATTRIBUTES)
        if len(conn.entries) != 1:
            raise RuntimeError('Expected one entry, found {}!'.format(len(conn.entries)))
        entry = conn.entries[0]
        return {
            'success': True,
            'displayName': entry.displayName.value,
        }
    else:
        print('Bind FAILED!')
        return {
            'success': False,
        }

def login(username, password, ldap_server, service_account_dn, service_account_password,
          base_dn, loginname_attribute, wait_seconds, marker_filter):
    """
    Given username, password and a LDAP configuration, attempt a login.
    :param username: login name of the user
    :param password: supplied password
    :param ldap_server: LDAP server IP
    :param service_account_dn: Distinguished Name of the service account
    :param service_account_password: Password of the service account
    :param base_dn: the base DN under which user search should be performed
    :param loginname_attribute: the attribute which contains the login name
    :param wait_seconds: Wait a specific number of seconds before issuing the second user bind request.
    :param marker_filter: something like "objectclass=App-something" to implement an app marker
    :return: dictionary with boolean key 'success'. In case of success, it also contains user information.
    """
    dn = lookup_user(username, ldap_server, service_account_dn, service_account_password,
                     base_dn, loginname_attribute, '(|({attr}={username})(%s))' % marker_filter)
    print('Given username {!r}, looked up dn: {!r}'.format(username, dn))
    print('[1] Connecting to LDAP server {!r} ...'.format(ldap_server))
    result1 = perform_login_search(dn, password, ldap_server)
    if not result1['success']:
        print('exiting ...')
        return result1
    print('Waiting for {!r} seconds ...'.format(wait_seconds))
    time.sleep(wait_seconds)
    print('[2] Connecting to LDAP server {!r} ...'.format(ldap_server))
    result2 = perform_login_search(dn, password, ldap_server)
    return result2

if __name__ == '__main__':
    with open('config.ini') as f:
        config = configobj.ConfigObj(f)
    password = config['password']
    if not password:
        password = input('Password? ')
    pprint(login(config['username'],
                 password,
                 config['ldap-server'],
                 config['service-account-dn'],
                 config['service-account-password'],
                 config['base-dn'],
                 config['loginname-attribute'],
                 int(config['wait-seconds']),
                 config['marker-filter']))