"""
Scenario 2) Web Application has no service account, performs user bind and search.

Given a user's login name, the web application can automatically determine the corresponding DN
(without having to ask the LDAP server). The web application issues a bind request on behalf of the
user and performs an LDAP search to retrieve the user's display name afterwards.
"""
from pprint import pprint

import ldap3
import configobj

from common import construct_dn

def login(username, password, ldap_server, base_dn, uid_attribute):
    """
    Given username, password and a LDAP configuration, attempt a login.
    :param username: login name of the user
    :param password: supplied password
    :param ldap_server: LDAP server IP
    :param base_dn: see `construct_dn`
    :param uid_attribute: see `construct_dn`
    :return: dictionary with boolean key 'success'. In case of success, it also contains user information.
    """
    dn = construct_dn(username, base_dn, uid_attribute)
    print('Given username {!r}, constructed dn: {!r}'.format(username, dn))
    print('Connecting to LDAP server {!r} ...'.format(ldap_server))
    conn = ldap3.Connection(ldap_server, user=dn, password=password)
    print('Bind with password {!r} ...'.format(password), end=' ')
    result = conn.bind()
    if result:
        print('Successful bind!')
        # Fetch user information
        conn.search(dn,
                    '(objectClass=*)',
                    attributes=ldap3.ALL_ATTRIBUTES)
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
                 config['base-dn'],
                 config['uid-attribute']))
