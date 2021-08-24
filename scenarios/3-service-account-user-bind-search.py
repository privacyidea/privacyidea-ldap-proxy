"""
Scenario 3) App uses a service account to look up user's DN and uses user search after bind.

Given a username, the app uses a service account to find the user's DN. For that, it performs an LDAP bind followed
by an LDAP server. After that, it issues a bind on behalf of the user and uses an LDAP search under the user's
context to retrieve profile information of the user.
"""
from pprint import pprint

import configobj
import ldap3
from common import lookup_user

def login(username, password, ldap_server, service_account_dn, service_account_password, base_dn, loginname_attribute):
    """
    Given username, password and a LDAP configuration, attempt a login.
    :param username: login name of the user
    :param password: supplied password
    :param ldap_server: LDAP server IP
    :param service_account_dn: Distinguished Name of the service account
    :param service_account_password: Password of the service account
    :param base_dn: the base DN under which user search should be performed
    :param loginname_attribute: the attribute which contains the login name
    :return: dictionary with boolean key 'success'. In case of success, it also contains user information.
    """
    dn = lookup_user(username, ldap_server, service_account_dn, service_account_password, base_dn, loginname_attribute)
    print('Given username {!r}, looked up dn: {!r}'.format(username, dn))
    print('Connecting to LDAP server {!r} ...'.format(ldap_server))
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
                 config['loginname-attribute']))